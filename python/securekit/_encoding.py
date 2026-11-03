"""Shared encodings. SPEC.md is normative; node/src/encoding.js must produce identical bytes."""

import base64
import re
import struct
import unicodedata

_B64U = re.compile(r"[A-Za-z0-9_-]*\Z")
_TRIM = (
    "\t\n\v\f\r              "
    "    　"
)
_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    """Strict unpadded base64url: other alphabets and non-canonical encodings raise ValueError."""
    if not isinstance(text, str) or not _B64U.match(text) or len(text) % 4 == 1:
        raise ValueError("invalid base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u_encode(raw) != text:
        raise ValueError("non-canonical base64url")
    return raw


def length_prefixed(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def utf8(text: str) -> bytes:
    """UTF-8 encode, rejecting lone surrogates (UnicodeEncodeError is a ValueError)."""
    return text.encode("utf-8")


def context(*parts) -> str:
    """Unambiguous join of strings and integers, e.g. context("users", "ssn", 42) == "5:users|3:ssn|2:42"."""
    if not parts:
        raise ValueError("context needs at least one part")
    encoded = []
    for part in parts:
        if isinstance(part, bool) or not isinstance(part, (str, int)):
            raise TypeError("context parts must be strings or integers")
        text = str(part)
        encoded.append(f"{len(utf8(text))}:{text}")
    return "|".join(encoded)


def normalize_text(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip(_TRIM).translate(_ASCII_LOWER)
