import hmac
import secrets
from typing import Union


def random_token(nbytes: int = 32) -> str:
    """URL-safe random token from the OS CSPRNG (password resets, session ids, API keys)."""
    if nbytes < 16:
        raise ValueError("tokens shorter than 16 bytes (128 bits) are guessable at scale")
    return secrets.token_urlsafe(nbytes)


def constant_time_equals(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """Timing-safe equality for secrets; str inputs are compared as UTF-8."""
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)
