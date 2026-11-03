import hashlib
import hmac
from typing import List

from ._encoding import normalize_text, utf8
from .keys import Keyring

MODES = ("text", "exact")


class BlindIndexer:
    """
    Keyed exact-match search tokens for encrypted columns.

    The column context is part of the key, so the same value in two columns gives unrelated
    indexes. An index reveals which rows hold equal plaintexts; it reveals nothing else without the key.
    """

    def __init__(self, keyring: Keyring, length_bytes: int = 16):
        if not 4 <= length_bytes <= 32:
            raise ValueError("length_bytes must be between 4 and 32")
        self._ring = keyring
        self._length = length_bytes

    def index(self, value: str, context: str, *, mode: str = "text") -> str:
        """`<kid>.<hex>` under the primary key; store it next to the encrypted column."""
        return self._index_for(self._ring.primary_kid, value, context, mode)

    def candidates(self, value: str, context: str, *, mode: str = "text") -> List[str]:
        """Indexes under every key in the ring, for `WHERE idx IN (...)` while rows are re-indexed."""
        return [self._index_for(kid, value, context, mode) for kid in self._ring.kids()]

    def _index_for(self, kid: str, value: str, context: str, mode: str) -> str:
        if not isinstance(value, str):
            raise TypeError("value must be str (handle NULLs before indexing)")
        if not isinstance(context, str) or not context:
            raise ValueError("context is required: use the table and column, e.g. context('users', 'email')")
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        data = utf8(normalize_text(value) if mode == "text" else value)
        key = self._ring.derive(kid, "blind", context)
        return f"{kid}.{hmac.new(key, data, hashlib.sha256).digest()[: self._length].hex()}"
