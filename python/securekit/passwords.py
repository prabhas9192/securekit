import unicodedata

from argon2 import PasswordHasher, extract_parameters, profiles
from argon2.exceptions import InvalidHashError, VerificationError

MAX_PASSWORD_BYTES = 4096
# Verification refuses stored hashes that demand more than this, so a tampered row cannot make the server
# allocate gigabytes. Same limits in the Node.js package.
MAX_MEMORY_KIB = 262144
MAX_PASSES = 10
MAX_PARALLELISM = 16

# RFC 9106 section 4, memory-constrained option: m=64 MiB, t=3, p=4, 16-byte salt, 32-byte tag.
_HASHER = PasswordHasher.from_parameters(profiles.RFC_9106_LOW_MEMORY)


def _prepare(password: str) -> str:
    """NFKC-normalize (NIST SP 800-63B) and bound the length."""
    if not isinstance(password, str):
        raise TypeError("password must be str")
    text = unicodedata.normalize("NFKC", password)
    size = len(text.encode("utf-8"))
    if not 1 <= size <= MAX_PASSWORD_BYTES:
        raise ValueError(f"password must be 1 to {MAX_PASSWORD_BYTES} bytes")
    return text


def hash_password(password: str) -> str:
    """Argon2id PHC string, e.g. `$argon2id$v=19$m=65536,t=3,p=4$...`."""
    return _HASHER.hash(_prepare(password))


def _within_limits(stored: str) -> bool:
    try:
        params = extract_parameters(stored)
    except (InvalidHashError, ValueError):
        return False
    return (
        params.version == 19
        and params.memory_cost <= MAX_MEMORY_KIB
        and params.time_cost <= MAX_PASSES
        and params.parallelism <= MAX_PARALLELISM
    )


def verify_password(password: str, stored: str) -> bool:
    """True only for a matching argon2id hash. Wrong passwords and malformed, foreign or oversized hashes give False."""
    if not isinstance(stored, str) or not stored.startswith("$argon2id$") or not _within_limits(stored):
        return False
    try:
        return _HASHER.verify(stored, _prepare(password))
    except (VerificationError, InvalidHashError, ValueError):
        return False


def needs_rehash(stored: str) -> bool:
    """True when the hash uses weaker or different parameters than the current ones (or is unreadable)."""
    try:
        return _HASHER.check_needs_rehash(stored)
    except (InvalidHashError, ValueError):
        return True
