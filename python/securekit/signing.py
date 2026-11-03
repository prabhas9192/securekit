import hashlib
import hmac
import re
import time
from typing import Optional, Union

from .keys import Keyring

_TIMESTAMP = re.compile(r"[0-9]{1,12}\Z")
_MAC_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _body_bytes(body: Union[str, bytes]) -> bytes:
    if isinstance(body, str):
        return body.encode("utf-8")
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    raise TypeError("body must be str or bytes")


class Signer:
    """Webhook-style request signing: `t=<unix>,kid=<kid>,v1=<hmac>` with replay-window checking."""

    def __init__(self, keyring: Keyring):
        self._ring = keyring

    def sign(self, body: Union[str, bytes], *, timestamp: Optional[int] = None) -> str:
        t = int(time.time()) if timestamp is None else timestamp
        if isinstance(t, bool) or not isinstance(t, int) or not 0 <= t < 10**12:
            raise ValueError("timestamp must be an integer number of seconds")
        kid = self._ring.primary_kid
        return f"t={t},kid={kid},v1={self._mac(kid, t, body)}"

    def verify(
        self,
        body: Union[str, bytes],
        header: str,
        *,
        tolerance_seconds: int = 300,
        now: Optional[float] = None,
    ) -> bool:
        """False for anything malformed, forged, stale or from the future; never raises on bad input."""
        fields = {}
        for part in header.split(",") if isinstance(header, str) else []:
            name, sep, value = part.partition("=")
            if not sep or name in fields:
                return False
            fields[name] = value
        if set(fields) != {"t", "kid", "v1"}:
            return False
        if not _TIMESTAMP.match(fields["t"]) or not _MAC_HEX.match(fields["v1"]) or not self._ring.has(fields["kid"]):
            return False
        t = int(fields["t"])
        current = time.time() if now is None else now
        if abs(current - t) > tolerance_seconds:
            return False
        return hmac.compare_digest(self._mac(fields["kid"], t, body), fields["v1"])

    def _mac(self, kid: str, t: int, body: Union[str, bytes]) -> str:
        key = self._ring.derive(kid, "sign")
        return hmac.new(key, f"{t}.".encode("ascii") + _body_bytes(body), hashlib.sha256).hexdigest()
