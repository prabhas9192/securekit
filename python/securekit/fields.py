import os
from typing import Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._encoding import b64u_decode, b64u_encode, utf8
from .errors import InvalidToken, UnknownKeyError
from .keys import Keyring

_VERSION = "sk1"
_NONCE_BYTES = 12
_TAG_BYTES = 16


def _aad(kid: str, context: str) -> bytes:
    if not isinstance(context, str) or not context:
        raise ValueError("context is required: bind every field to its table, column and row (see securekit.context)")
    return b"securekit/v1/field\x00" + kid.encode("ascii") + b"\x00" + utf8(context)


def _as_bytes(plaintext: Union[str, bytes]) -> bytes:
    if isinstance(plaintext, str):
        return utf8(plaintext)
    if isinstance(plaintext, (bytes, bytearray, memoryview)):
        return bytes(plaintext)
    raise TypeError("plaintext must be str or bytes")


class FieldCipher:
    """AES-256-GCM field encryption with key ids, mandatory context binding and rotation."""

    def __init__(self, keyring: Keyring):
        self._ring = keyring

    def encrypt(self, plaintext: Union[str, bytes], context: str) -> str:
        data = _as_bytes(plaintext)
        kid = self._ring.primary_kid
        nonce = os.urandom(_NONCE_BYTES)
        sealed = AESGCM(self._ring.derive(kid, "field")).encrypt(nonce, data, _aad(kid, context))
        return f"{_VERSION}.{kid}.{b64u_encode(nonce + sealed)}"

    def decrypt(self, token: str, context: str) -> bytes:
        kid, raw = self._parse(token)
        try:
            return AESGCM(self._ring.derive(kid, "field")).decrypt(raw[:_NONCE_BYTES], raw[_NONCE_BYTES:], _aad(kid, context))
        except InvalidTag:
            raise InvalidToken("invalid token") from None

    def decrypt_str(self, token: str, context: str) -> str:
        try:
            return self.decrypt(token, context).decode("utf-8")
        except UnicodeDecodeError:
            raise InvalidToken("invalid token") from None

    def needs_rotation(self, token: str) -> bool:
        """True when the token was written under a key id other than the current primary."""
        kid, _ = self._parse(token)
        return kid != self._ring.primary_kid

    def rotate(self, token: str, context: str) -> str:
        """Re-encrypts under the primary key; returns the token unchanged if it already is."""
        if not self.needs_rotation(token):
            return token
        return self.encrypt(self.decrypt(token, context), context)

    def _parse(self, token: str) -> Tuple[str, bytes]:
        parts = token.split(".") if isinstance(token, str) else []
        if len(parts) != 3 or parts[0] != _VERSION:
            raise InvalidToken("invalid token")
        kid = parts[1]
        if not self._ring.has(kid):
            raise UnknownKeyError(f"unknown key id {kid!r}")
        try:
            raw = b64u_decode(parts[2])
        except ValueError:
            raise InvalidToken("invalid token") from None
        if len(raw) < _NONCE_BYTES + _TAG_BYTES:
            raise InvalidToken("invalid token")
        return kid, raw
