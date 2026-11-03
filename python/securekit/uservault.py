"""
Per-user vault (SPEC.md section 8): data the server must not be able to read.

    vault, recovery_key = UserVault.create("user-42", passphrase, with_recovery=True)
    state = vault.state                              # store this JSON next to the user; it holds no usable secret
    token = vault.encrypt_item("note-1", "my private note")     # store the token

    vault = UserVault.unlock("user-42", state, passphrase)      # the passphrase never leaves the client
    vault.decrypt_item("note-1", token)

A random data key encrypts the items; the data key is wrapped under a key derived from the passphrase with Argon2id.
Changing the passphrase re-wraps one key and leaves every item untouched. Forget the passphrase without a recovery key
and the data is gone: that is the point, and there is no reset.
"""

import secrets
import unicodedata
from typing import Any, Dict, Optional, Tuple, Union

from argon2.low_level import Type, hash_secret_raw

from ._encoding import b64u_decode, b64u_encode, context
from .errors import InvalidToken, SecureKitError, WrongPassphraseError
from .fields import FieldCipher
from .keys import Keyring, generate_key

FORMAT = "securekit-uservault/1"
MIN_PASSPHRASE_CHARS = 8
MAX_PASSPHRASE_BYTES = 4096
_PARAMS = {"m": 65536, "t": 3, "p": 4}
_LIMITS = {"m": 262144, "t": 10, "p": 16}  # same caps as password verification: a tampered state cannot demand gigabytes

Ident = Union[str, int]


def _kek(passphrase: str, kdf: Dict[str, Any]) -> str:
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be str")
    text = unicodedata.normalize("NFKC", passphrase)
    data = text.encode("utf-8")
    if not 1 <= len(data) <= MAX_PASSPHRASE_BYTES:
        raise ValueError(f"passphrase must be 1 to {MAX_PASSPHRASE_BYTES} bytes")
    raw = hash_secret_raw(
        secret=data, salt=b64u_decode(kdf["salt"]), time_cost=kdf["t"], memory_cost=kdf["m"],
        parallelism=kdf["p"], hash_len=32, type=Type.ID, version=19,
    )
    return b64u_encode(raw)


def _check_new_passphrase(passphrase: str) -> None:
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be str")
    if len(unicodedata.normalize("NFKC", passphrase)) < MIN_PASSPHRASE_CHARS:
        raise ValueError(f"choose a passphrase of at least {MIN_PASSPHRASE_CHARS} characters")


def _fresh_kdf() -> Dict[str, Any]:
    return {"alg": "argon2id", **_PARAMS, "salt": b64u_encode(secrets.token_bytes(16))}


def _check_state(state: Any) -> Dict[str, Any]:
    ok = isinstance(state, dict) and state.get("format") == FORMAT and isinstance(state.get("wrapped_key"), str)
    kdf = state.get("kdf") if ok else None
    ok = ok and isinstance(kdf, dict) and set(kdf) == {"alg", "m", "t", "p", "salt"} and kdf["alg"] == "argon2id"
    ok = ok and all(isinstance(kdf[k], int) and not isinstance(kdf[k], bool) and 1 <= kdf[k] <= _LIMITS[k] for k in ("m", "t", "p"))
    ok = ok and kdf["m"] >= 8 * kdf["p"] and isinstance(kdf["salt"], str)
    ok = ok and (state.get("recovery_wrapped_key") is None or isinstance(state.get("recovery_wrapped_key"), str))
    if ok:
        try:
            ok = len(b64u_decode(kdf["salt"])) >= 8
        except ValueError:
            ok = False
    if not ok:
        raise SecureKitError("malformed or unsupported user vault state")
    return state


def _single(key_id: str, root_key: str) -> FieldCipher:
    return FieldCipher(Keyring({key_id: root_key}, key_id))


class UserVault:
    def __init__(self, user_id: Ident, data_key: bytes, state: Dict[str, Any]):
        self._user_id = user_id
        self._data_key = data_key
        self._items = _single("d1", b64u_encode(data_key))
        self._state = state

    @property
    def state(self) -> Dict[str, Any]:
        """JSON-serializable state to store with the user. Contains only wrapped keys and KDF parameters."""
        return {**self._state, "kdf": dict(self._state["kdf"])}

    # ------------------------------------------------------------------ creating and unlocking

    @classmethod
    def create(cls, user_id: Ident, passphrase: str, *, with_recovery: bool = False) -> Tuple["UserVault", Optional[str]]:
        """Returns (vault, recovery_key). Show the recovery key to the user once; it is not stored anywhere."""
        _check_new_passphrase(passphrase)
        data_key = secrets.token_bytes(32)
        kdf = _fresh_kdf()
        state = {"format": FORMAT, "kdf": kdf, "recovery_wrapped_key": None,
                 "wrapped_key": _single("u1", _kek(passphrase, kdf)).encrypt(data_key, context("uservault", user_id, "dek"))}
        vault = cls(user_id, data_key, state)
        return vault, (vault.new_recovery_key() if with_recovery else None)

    @classmethod
    def unlock(cls, user_id: Ident, state: Dict[str, Any], passphrase: str) -> "UserVault":
        _check_state(state)
        try:
            data_key = _single("u1", _kek(passphrase, state["kdf"])).decrypt(state["wrapped_key"], context("uservault", user_id, "dek"))
        except InvalidToken:
            raise WrongPassphraseError("wrong passphrase, or this state belongs to another user") from None
        return cls(user_id, cls._valid_key(data_key), dict(state))

    @classmethod
    def unlock_with_recovery(cls, user_id: Ident, state: Dict[str, Any], recovery_key: str) -> "UserVault":
        _check_state(state)
        if state.get("recovery_wrapped_key") is None:
            raise SecureKitError("this vault has no recovery key")
        try:
            data_key = _single("r1", recovery_key).decrypt(state["recovery_wrapped_key"], context("uservault", user_id, "dek-recovery"))
        except (InvalidToken, ValueError):
            raise WrongPassphraseError("wrong recovery key, or this state belongs to another user") from None
        return cls(user_id, cls._valid_key(data_key), dict(state))

    @staticmethod
    def _valid_key(data_key: bytes) -> bytes:
        if len(data_key) != 32:
            raise SecureKitError("malformed user vault state")
        return data_key

    # ------------------------------------------------------------------ items

    def encrypt_item(self, item_id: Ident, plaintext: Union[str, bytes]) -> str:
        return self._items.encrypt(plaintext, context("uservault", self._user_id, item_id))

    def decrypt_item(self, item_id: Ident, token: str) -> bytes:
        return self._items.decrypt(token, context("uservault", self._user_id, item_id))

    def decrypt_item_str(self, item_id: Ident, token: str) -> str:
        return self._items.decrypt_str(token, context("uservault", self._user_id, item_id))

    # ------------------------------------------------------------------ credential changes

    def change_passphrase(self, new_passphrase: str) -> Dict[str, Any]:
        """Re-wrap the data key under a new passphrase. Items stay as they are. Returns (and keeps) the new state."""
        _check_new_passphrase(new_passphrase)
        kdf = _fresh_kdf()
        self._state = {**self._state, "kdf": kdf,
                       "wrapped_key": _single("u1", _kek(new_passphrase, kdf)).encrypt(self._data_key, context("uservault", self._user_id, "dek"))}
        return self.state

    def new_recovery_key(self) -> str:
        """Create (or replace) the recovery key. Any earlier recovery key stops working once the new state is stored."""
        recovery_key = generate_key()
        self._state = {**self._state,
                       "recovery_wrapped_key": _single("r1", recovery_key).encrypt(self._data_key, context("uservault", self._user_id, "dek-recovery"))}
        return recovery_key
