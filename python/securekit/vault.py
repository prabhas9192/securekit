"""
Encrypted secrets vault for applications (SPEC.md section 7).

    ring = Keyring.from_env()
    vault = Vault.create("secrets.vault.json", ring, actor="deploy")      # once
    vault = Vault.open("secrets.vault.json", ring, actor="payments-api")  # at startup
    vault.put("payments/stripe_key", "sk_live_...")
    key = vault.get_str("payments/stripe_key")

Every secret version is encrypted under the keyring, bound to the vault, name and version. The file carries a
manifest (detects edited, swapped, removed or added entries) and a hash-chained audit log. A process that holds the
keyring can read everything in the vault: use scoped() to limit what a component of your own code can reach, and
a real secrets server if you need per-client authorization.
"""

import hashlib
import json
import os
import re
import secrets
import time
from typing import Any, Callable, Dict, List, Optional, Union

from ._encoding import b64u_encode, context
from .errors import (
    InvalidToken,
    SecretNotFoundError,
    SecureKitError,
    TamperedVaultError,
    VaultExistsError,
    VaultLockedError,
)
from .fields import FieldCipher
from .keys import Keyring
from .seal import RecordSealer

FORMAT = "securekit-vault/1"
MAX_VALUE_BYTES = 1_048_576
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_ACTOR = re.compile(r"[^\x00-\x1f\x7f]{1,128}\Z")
_ACTIONS = {"init", "put", "read", "destroy", "delete", "rotate-keys"}


def check_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME.match(name) or any(part in ("", ".", "..") for part in name.split("/")):
        raise ValueError(
            "secret names use 1-128 characters from A-Z a-z 0-9 . _ - and / between non-empty segments, "
            "starting with a letter or digit"
        )
    return name


def _check_actor(actor: str) -> str:
    if not isinstance(actor, str) or not _ACTOR.match(actor):
        raise ValueError("actor must be 1-128 characters without control characters")
    return actor


def _sort_key(name: str) -> bytes:
    return name.encode("utf-8")


class _FileLock:
    """Exclusive `<vault>.lock` file (create-exclusive). A lock older than stale_after seconds is treated as abandoned."""

    def __init__(self, path: str, timeout: float = 10.0, stale_after: float = 120.0):
        self._path, self._timeout, self._stale_after = path, timeout, stale_after

    def __enter__(self):
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(fd, str(os.getpid()).encode("ascii"))
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    if time.time() - os.stat(self._path).st_mtime > self._stale_after:
                        os.unlink(self._path)
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() >= deadline:
                    raise VaultLockedError(f"could not lock the vault ({self._path}); another process is writing to it") from None
                time.sleep(0.05)

    def __exit__(self, *exc):
        try:
            os.unlink(self._path)
        except FileNotFoundError:
            pass


class Vault:
    def __init__(self, path, keyring, *, actor, audit_reads, clock, verify_audit, lock_timeout):
        self._path = os.fspath(path)
        self._ring = keyring
        self._cipher = FieldCipher(keyring)
        self._sealer = RecordSealer(keyring)
        self._actor = _check_actor(actor)
        self._audit_reads = audit_reads
        self._clock = clock
        self._verify_audit = verify_audit
        self._lock_timeout = lock_timeout
        self._data: Dict[str, Any] = {}
        self._file_state = None

    # ------------------------------------------------------------------ construction

    @classmethod
    def create(cls, path, keyring: Keyring, *, actor: str = "system", clock: Callable[[], int] = lambda: int(time.time()),
               lock_timeout: float = 10.0) -> "Vault":
        vault = cls(path, keyring, actor=actor, audit_reads=False, clock=clock, verify_audit=True, lock_timeout=lock_timeout)
        with _FileLock(vault._path + ".lock", lock_timeout):
            if os.path.exists(vault._path):
                raise VaultExistsError(f"a vault already exists at {vault._path}")
            now = clock()
            data = {"format": FORMAT, "id": b64u_encode(secrets.token_bytes(16)), "created": now, "generation": 0,
                    "secrets": {}, "audit": [], "manifest": ""}
            vault._append_audit(data, "init", None, None)
            data["manifest"] = vault._manifest(data)
            vault._write(data)
            vault._data = data
            vault._file_state = vault._stat_state()
        return vault

    @classmethod
    def open(cls, path, keyring: Keyring, *, actor: str = "system", audit_reads: bool = False,
             clock: Callable[[], int] = lambda: int(time.time()), verify_audit: bool = True, lock_timeout: float = 10.0) -> "Vault":
        vault = cls(path, keyring, actor=actor, audit_reads=audit_reads, clock=clock, verify_audit=verify_audit, lock_timeout=lock_timeout)
        vault._reload()
        return vault

    # ------------------------------------------------------------------ reading

    def names(self) -> List[str]:
        data = self._current()
        return sorted((n for n, e in data["secrets"].items() if any(v["state"] == "active" for v in e["versions"])), key=_sort_key)

    def versions(self, name: str) -> List[Dict[str, Any]]:
        """Metadata only (version, created, by, state); never the value."""
        entry = self._current()["secrets"].get(check_name(name))
        if entry is None:
            raise SecretNotFoundError(f"no secret named {name!r}")
        return [{"version": v["v"], "created": v["created"], "by": v["by"], "state": v["state"]} for v in entry["versions"]]

    def get(self, name: str, *, version: Optional[int] = None) -> bytes:
        data = self._current()
        entry = data["secrets"].get(check_name(name))
        active = [v for v in (entry["versions"] if entry else []) if v["state"] == "active"]
        if version is None:
            chosen = active[-1] if active else None
        else:
            chosen = next((v for v in active if v["v"] == version), None)
        if chosen is None:
            raise SecretNotFoundError(f"no active secret {name!r}" + (f" version {version}" if version is not None else ""))
        try:
            value = self._cipher.decrypt(chosen["token"], context("vault", data["id"], name, chosen["v"]))
        except InvalidToken as error:
            raise TamperedVaultError(f"secret {name!r} v{chosen['v']} does not decrypt: wrong keyring or modified vault") from error
        if self._audit_reads:
            self._mutate(lambda d, emit: emit("read", name, chosen["v"]))
        return value

    def get_str(self, name: str, *, version: Optional[int] = None) -> str:
        return self.get(name, version=version).decode("utf-8")

    def audit(self) -> List[Dict[str, Any]]:
        return [dict(entry) for entry in self._current()["audit"]]

    def verify(self, *, deep: bool = False) -> None:
        """Re-read the file and check every integrity property. deep=True also decrypts every active secret."""
        self._reload()
        if deep:
            data = self._data
            for name, entry in data["secrets"].items():
                for v in entry["versions"]:
                    if v["state"] == "active":
                        try:
                            self._cipher.decrypt(v["token"], context("vault", data["id"], name, v["v"]))
                        except InvalidToken as error:
                            raise TamperedVaultError(f"secret {name!r} v{v['v']} does not decrypt") from error

    def scoped(self, prefix: str) -> "ScopedVault":
        """A view limited to names under `prefix` (for example "payments/"), to give one component only its own secrets."""
        return ScopedVault(self, prefix)

    # ------------------------------------------------------------------ writing

    def put(self, name: str, value: Union[str, bytes], *, retain: int = 10) -> int:
        """Store a new version and return its number. Only the newest `retain` active versions are kept."""
        check_name(name)
        data_bytes = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        if not data_bytes or len(data_bytes) > MAX_VALUE_BYTES:
            raise ValueError(f"a secret must be 1 to {MAX_VALUE_BYTES} bytes")
        if retain < 1:
            raise ValueError("retain must be at least 1")

        def apply(data, emit):
            entry = data["secrets"].setdefault(name, {"versions": []})
            number = max((v["v"] for v in entry["versions"]), default=0) + 1
            token = self._cipher.encrypt(data_bytes, context("vault", data["id"], name, number))
            entry["versions"].append({"v": number, "created": self._clock(), "by": self._actor, "state": "active", "token": token})
            emit("put", name, number)
            active = [v for v in entry["versions"] if v["state"] == "active"]
            for old in active[:-retain]:
                old["state"], old["token"] = "destroyed", None
                emit("destroy", name, old["v"])
            return number

        return self._mutate(apply)

    def destroy(self, name: str, version: int) -> None:
        """Irreversibly remove one version's ciphertext."""
        check_name(name)

        def apply(data, emit):
            entry = data["secrets"].get(name)
            target = next((v for v in (entry["versions"] if entry else []) if v["v"] == version and v["state"] == "active"), None)
            if target is None:
                raise SecretNotFoundError(f"no active secret {name!r} version {version}")
            target["state"], target["token"] = "destroyed", None
            emit("destroy", name, version)

        self._mutate(apply)

    def delete(self, name: str) -> None:
        """Destroy every version of a secret. The name and the audit trail remain."""
        check_name(name)

        def apply(data, emit):
            entry = data["secrets"].get(name)
            active = [v for v in (entry["versions"] if entry else []) if v["state"] == "active"]
            if not active:
                raise SecretNotFoundError(f"no active secret {name!r}")
            for v in active:
                v["state"], v["token"] = "destroyed", None
            emit("delete", name, None)

        self._mutate(apply)

    def rotate_keys(self) -> int:
        """Re-encrypt every active secret under the keyring's primary key; returns how many were rewritten."""

        def apply(data, emit):
            count = 0
            for name in sorted(data["secrets"], key=_sort_key):
                for v in data["secrets"][name]["versions"]:
                    if v["state"] == "active":
                        fresh = self._cipher.rotate(v["token"], context("vault", data["id"], name, v["v"]))
                        if fresh != v["token"]:
                            v["token"] = fresh
                            count += 1
            emit("rotate-keys", None, None)
            return count

        return self._mutate(apply)

    # ------------------------------------------------------------------ internals

    def _mutate(self, apply: Callable[[Dict[str, Any], Callable], Any]):
        with _FileLock(self._path + ".lock", self._lock_timeout):
            data = self._read_verified()
            events: List[tuple] = []
            result = apply(data, lambda action, name, version: events.append((action, name, version)))
            for action, name, version in events:
                self._append_audit(data, action, name, version)
            data["generation"] += 1
            data["manifest"] = self._manifest(data)
            self._write(data)
            self._data = data
            self._file_state = self._stat_state()
            return result

    def _current(self) -> Dict[str, Any]:
        if self._file_state != self._stat_state():
            self._reload()
        return self._data

    def _reload(self) -> None:
        self._data = self._read_verified()
        self._file_state = self._stat_state()

    def _stat_state(self):
        try:
            stat = os.stat(self._path)
        except FileNotFoundError:
            return None
        return (stat.st_mtime_ns, stat.st_size, stat.st_ino)

    def _read_verified(self) -> Dict[str, Any]:
        try:
            with open(self._path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            raise SecureKitError(f"no vault at {self._path}; create one with Vault.create") from None
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise TamperedVaultError("the vault file is not valid JSON") from error
        self._check_structure(data)
        if not self._sealer.verify(self._manifest_record(data), context("vault", data["id"], "manifest"), data["manifest"]):
            raise TamperedVaultError("the vault manifest does not match its contents (edited, truncated or wrong keyring)")
        if self._verify_audit:
            self._check_audit(data)
        return data

    @staticmethod
    def _check_structure(data: Any) -> None:
        def bad(reason):
            raise TamperedVaultError(f"malformed vault: {reason}")

        if not isinstance(data, dict) or data.get("format") != FORMAT:
            bad("unknown format")
        for key, kind in (("id", str), ("created", int), ("generation", int), ("manifest", str), ("secrets", dict), ("audit", list)):
            if not isinstance(data.get(key), kind) or isinstance(data.get(key), bool):
                bad(f"{key} has the wrong type")
        for name, entry in data["secrets"].items():
            try:
                check_name(name)
            except ValueError:
                bad("invalid secret name")
            versions = entry.get("versions") if isinstance(entry, dict) else None
            if not isinstance(versions, list) or not versions:
                bad(f"{name!r} has no version list")
            last = 0
            for v in versions:
                if not isinstance(v, dict) or set(v) != {"v", "created", "by", "state", "token"}:
                    bad(f"{name!r} has a malformed version")
                if not (isinstance(v["v"], int) and not isinstance(v["v"], bool) and v["v"] > last):
                    bad(f"{name!r} versions are not increasing")
                last = v["v"]
                if not (isinstance(v["created"], int) and isinstance(v["by"], str) and _ACTOR.match(v["by"])):
                    bad(f"{name!r} has bad metadata")
                if v["state"] == "active" and isinstance(v["token"], str):
                    continue
                if v["state"] == "destroyed" and v["token"] is None:
                    continue
                bad(f"{name!r} has an inconsistent state")

    def _check_audit(self, data: Dict[str, Any]) -> None:
        previous = ""
        for index, entry in enumerate(data["audit"], start=1):
            ok = (
                isinstance(entry, dict)
                and set(entry) == {"seq", "ts", "actor", "action", "name", "version", "prev", "seal"}
                and entry["seq"] == index
                and entry["prev"] == previous
                and entry["action"] in _ACTIONS
            )
            if not ok:
                raise TamperedVaultError(f"audit entry {index} is out of sequence or malformed")
            record = {k: entry[k] for k in ("seq", "ts", "actor", "action", "name", "version", "prev")}
            try:
                valid = self._sealer.verify(record, context("vault", data["id"], "audit"), entry["seal"])
            except (TypeError, ValueError):
                valid = False
            if not valid:
                raise TamperedVaultError(f"audit entry {index} fails its seal (edited, or sealed under a key that is not in this keyring)")
            previous = entry["seal"]

    def _append_audit(self, data: Dict[str, Any], action: str, name: Optional[str], version: Optional[int]) -> None:
        previous = data["audit"][-1]["seal"] if data["audit"] else ""
        record = {"seq": len(data["audit"]) + 1, "ts": self._clock(), "actor": self._actor, "action": action,
                  "name": name, "version": version, "prev": previous}
        record["seal"] = self._sealer.seal(record, context("vault", data["id"], "audit"))
        data["audit"].append(record)

    @staticmethod
    def _index(data: Dict[str, Any]) -> str:
        lines = []
        for name in sorted(data["secrets"], key=_sort_key):
            for v in data["secrets"][name]["versions"]:
                digest = hashlib.sha256((v["token"] or "").encode("utf-8")).hexdigest()
                lines.append("\t".join([name, str(v["v"]), v["state"], str(v["created"]), v["by"], digest]))
        return "\n".join(lines)

    def _manifest_record(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "format": FORMAT, "id": data["id"], "created": data["created"], "generation": data["generation"],
            "audit_head": data["audit"][-1]["seal"] if data["audit"] else "", "audit_count": len(data["audit"]),
            "index": self._index(data),
        }

    def _manifest(self, data: Dict[str, Any]) -> str:
        return self._sealer.seal(self._manifest_record(data), context("vault", data["id"], "manifest"))

    def _write(self, data: Dict[str, Any]) -> None:
        temporary = f"{self._path}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._path)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        try:  # make the rename durable where the platform allows it
            directory = os.open(os.path.dirname(os.path.abspath(self._path)), os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            pass


class ScopedVault:
    """Read/write access to the names under one prefix of a Vault."""

    def __init__(self, vault: Vault, prefix: str):
        if not prefix.endswith("/"):
            raise ValueError("a scope prefix ends with '/', for example 'payments/'")
        check_name(prefix + "x")
        self._vault, self._prefix = vault, prefix

    def _allow(self, name: str) -> str:
        if not check_name(name).startswith(self._prefix):
            raise SecretNotFoundError(f"{name!r} is outside the scope {self._prefix!r}")
        return name

    def names(self) -> List[str]:
        return [n for n in self._vault.names() if n.startswith(self._prefix)]

    def get(self, name: str, *, version: Optional[int] = None) -> bytes:
        return self._vault.get(self._allow(name), version=version)

    def get_str(self, name: str, *, version: Optional[int] = None) -> str:
        return self._vault.get_str(self._allow(name), version=version)

    def put(self, name: str, value: Union[str, bytes], *, retain: int = 10) -> int:
        return self._vault.put(self._allow(name), value, retain=retain)
