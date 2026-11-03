import json
import os
import re
import secrets
from typing import List, Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._encoding import b64u_decode, b64u_encode, utf8
from .errors import SecureKitError, UnknownKeyError

KEY_BYTES = 32
MAX_INFO_BYTES = 1024  # Node's hkdfSync limit; enforced here too so both languages accept the same inputs
_KID = re.compile(r"[A-Za-z0-9_-]{1,16}\Z")


def generate_key() -> str:
    """A new root key: 32 bytes from the OS CSPRNG, base64url encoded."""
    return b64u_encode(secrets.token_bytes(KEY_BYTES))


class Keyring:
    """
    Root keys by key id, with one primary used for new data.

    Root keys must be 32 random bytes (see generate_key). Passphrases are rejected on purpose:
    nothing here stretches them. To use a KMS, fetch the data keys at startup and build a Keyring
    from them (envelope encryption); the root keys never need to be stored next to the data.
    """

    def __init__(self, keys: Mapping[str, str], primary: str):
        if not keys:
            raise ValueError("a keyring needs at least one key")
        parsed = {}
        for kid, encoded in keys.items():
            if not isinstance(kid, str) or not _KID.match(kid):
                raise ValueError(f"invalid key id {kid!r}: use 1-16 characters from A-Z a-z 0-9 _ -")
            try:
                raw = b64u_decode(encoded)
            except ValueError:
                raise ValueError(f"key {kid!r} is not valid base64url; create keys with generate_key()") from None
            if len(raw) != KEY_BYTES:
                raise ValueError(f"key {kid!r} must be exactly {KEY_BYTES} random bytes; create keys with generate_key()")
            parsed[kid] = raw
        if primary not in parsed:
            raise ValueError(f"primary key id {primary!r} is not in the keyring")
        self._keys = parsed
        self._primary = primary

    @classmethod
    def from_json(cls, text: str) -> "Keyring":
        """Reads {"primary": "k2", "keys": {"k1": "<key>", "k2": "<key>"}}."""
        data = json.loads(text)
        return cls(data["keys"], data["primary"])

    @classmethod
    def from_env(cls, name: str = "SECUREKIT_KEYRING") -> "Keyring":
        text = os.environ.get(name)
        if not text:
            raise SecureKitError(f"environment variable {name} is not set")
        return cls.from_json(text)

    @property
    def primary_kid(self) -> str:
        return self._primary

    def kids(self) -> List[str]:
        return list(self._keys)

    def has(self, kid: str) -> bool:
        return kid in self._keys

    def derive(self, kid: str, purpose: str, suffix: str = "") -> bytes:
        """32-byte sub-key for a purpose (and optional suffix such as a column context)."""
        try:
            root = self._keys[kid]
        except KeyError:
            raise UnknownKeyError(f"unknown key id {kid!r}") from None
        info = utf8(f"securekit/v1/{purpose}" + (f"/{suffix}" if suffix else ""))
        if len(info) > MAX_INFO_BYTES:
            raise ValueError(f"context is too long: sub-key info is limited to {MAX_INFO_BYTES} bytes")
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(root)

    def __repr__(self) -> str:
        return f"Keyring(kids={self.kids()}, primary={self._primary!r})"
