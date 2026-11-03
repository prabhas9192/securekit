"""
securekit: a thin, opinionated layer over `cryptography` and `argon2-cffi`.

No primitives are implemented here. See ../SPEC.md for the wire formats shared with the Node.js package.
"""

from ._encoding import context, normalize_text
from .blind import BlindIndexer
from .errors import InvalidToken, SecureKitError, UnknownKeyError
from .fields import FieldCipher
from .keys import Keyring, generate_key
from .passwords import hash_password, needs_rehash, verify_password
from .seal import RecordSealer
from .signing import Signer
from .tokens import constant_time_equals, random_token

__all__ = [
    "BlindIndexer",
    "FieldCipher",
    "InvalidToken",
    "Keyring",
    "RecordSealer",
    "SecureKitError",
    "Signer",
    "UnknownKeyError",
    "constant_time_equals",
    "context",
    "generate_key",
    "hash_password",
    "needs_rehash",
    "normalize_text",
    "random_token",
    "verify_password",
]
