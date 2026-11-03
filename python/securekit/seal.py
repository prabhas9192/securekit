import hashlib
import hmac
import struct
from typing import Any, Iterable, Mapping, Optional

from ._encoding import b64u_decode, b64u_encode, length_prefixed, utf8
from .keys import Keyring

_VERSION = "sk1s"
_NULL, _STR, _INT, _BOOL, _BYTES = 0, 1, 2, 3, 4


def _encode_value(value: Any):
    if value is None:
        return _NULL, b""
    if isinstance(value, bool):
        return _BOOL, b"1" if value else b"0"
    if isinstance(value, int):
        return _INT, str(value).encode("ascii")
    if isinstance(value, str):
        return _STR, utf8(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _BYTES, bytes(value)
    raise TypeError(
        f"cannot seal a {type(value).__name__}: convert it to str, int, bool, bytes or None first "
        "(floats and datetimes have no single canonical form)"
    )


def _message(record: Mapping[str, Any], context: str, exclude: Iterable[str]) -> bytes:
    if not isinstance(context, str) or not context:
        raise ValueError("context is required: bind the seal to its table and row id")
    skip = set(exclude)
    entries = []
    for key, value in record.items():
        if not isinstance(key, str) or not key:
            raise TypeError("record keys must be non-empty strings")
        if key not in skip:
            entries.append((utf8(key), value))
    entries.sort(key=lambda entry: entry[0])

    parts = [b"securekit/v1/seal\x00", length_prefixed(utf8(context)), struct.pack(">I", len(entries))]
    for key, value in entries:
        kind, data = _encode_value(value)
        parts += [length_prefixed(key), bytes([kind]), length_prefixed(data)]
    return b"".join(parts)


class RecordSealer:
    """
    Tamper-evidence for plaintext columns: an HMAC over every field of the record plus its context.

    Every key is sealed unless named in `exclude`; nothing is skipped by name pattern, so columns
    like password_hash are covered. Include a version counter in the record if you also need to
    detect rollback to an older valid row.
    """

    def __init__(self, keyring: Keyring):
        self._ring = keyring

    def seal(self, record: Mapping[str, Any], context: str, *, exclude: Iterable[str] = ()) -> str:
        kid = self._ring.primary_kid
        return f"{_VERSION}.{kid}.{self._mac(kid, record, context, exclude)}"

    def verify(self, record: Mapping[str, Any], context: str, seal: str, *, exclude: Iterable[str] = ()) -> bool:
        parts = seal.split(".") if isinstance(seal, str) else []
        if len(parts) != 3 or parts[0] != _VERSION or not self._ring.has(parts[1]):
            return False
        try:
            b64u_decode(parts[2])
        except ValueError:
            return False
        expected = self._mac(parts[1], record, context, exclude)
        return hmac.compare_digest(expected, parts[2])

    def _mac(self, kid: str, record, context, exclude) -> str:
        key = self._ring.derive(kid, "seal")
        return b64u_encode(hmac.new(key, _message(record, context, exclude), hashlib.sha256).digest())
