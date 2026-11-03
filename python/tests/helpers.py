"""Fixed TEST-ONLY keys. Never use these for real data."""

from securekit import Keyring
from securekit._encoding import b64u_encode

KEY_K1 = b64u_encode(bytes(range(32)))
KEY_K2 = b64u_encode(bytes(range(32, 64)))
KEY_K3 = b64u_encode(bytes(range(64, 96)))


def ring(primary="k2", kids=("k1", "k2")):
    keys = {"k1": KEY_K1, "k2": KEY_K2, "k3": KEY_K3}
    return Keyring({kid: keys[kid] for kid in kids}, primary)


def record_from_triples(triples):
    """[[key, type, value], ...] (the vectors.json record format) -> dict."""
    record = {}
    for key, kind, value in triples:
        if kind == "null":
            record[key] = None
        elif kind == "str":
            record[key] = value
        elif kind == "int":
            record[key] = int(value)
        elif kind == "bool":
            record[key] = bool(value)
        elif kind == "bytes":
            record[key] = bytes.fromhex(value)
        else:
            raise ValueError(kind)
    return record
