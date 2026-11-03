import hashlib
import hmac
import os
import unittest
from unittest import mock

from securekit import Keyring, SecureKitError, UnknownKeyError, generate_key
from securekit._encoding import b64u_decode, b64u_encode
from tests.helpers import KEY_K1, KEY_K2, ring


def hkdf_sha256_single_block(ikm: bytes, info: bytes) -> bytes:
    """Independent RFC 5869 implementation (salt omitted, L = 32) to check Keyring.derive against."""
    prk = hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


class KeyringTests(unittest.TestCase):
    def test_generate_key_is_32_random_bytes(self):
        first, second = generate_key(), generate_key()
        self.assertNotEqual(first, second)
        self.assertEqual(len(b64u_decode(first)), 32)

    def test_rejects_passphrases_and_wrong_lengths(self):
        for bad in (
            "MasterDatabaseSecretKey2026!",
            "short",
            "",
            b64u_encode(bytes(16)),
            b64u_encode(bytes(33)),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    Keyring({"k1": bad}, "k1")

    def test_rejects_bad_key_ids_and_structure(self):
        for kid in ("", "has space", "a.b", "x" * 17):
            with self.subTest(kid=kid):
                with self.assertRaises(ValueError):
                    Keyring({kid: KEY_K1}, kid)
        with self.assertRaises(ValueError):
            Keyring({}, "k1")
        with self.assertRaises(ValueError):
            Keyring({"k1": KEY_K1}, "k2")

    def test_repr_never_contains_key_material(self):
        text = repr(ring())
        self.assertNotIn(KEY_K1, text)
        self.assertNotIn(KEY_K2, text)
        self.assertIn("k2", text)

    def test_json_and_environment_loading(self):
        text = '{"primary": "k1", "keys": {"k1": "%s"}}' % KEY_K1
        self.assertEqual(Keyring.from_json(text).primary_kid, "k1")
        with mock.patch.dict(os.environ, {"SECUREKIT_KEYRING": text}):
            self.assertEqual(Keyring.from_env().kids(), ["k1"])
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(SecureKitError):
                Keyring.from_env()

    def test_subkeys_match_independent_hkdf(self):
        root = b64u_decode(KEY_K1)
        r = ring()
        self.assertEqual(r.derive("k1", "field"), hkdf_sha256_single_block(root, b"securekit/v1/field"))
        self.assertEqual(r.derive("k1", "blind", "users/email"), hkdf_sha256_single_block(root, b"securekit/v1/blind/users/email"))

    def test_subkeys_are_separated_by_purpose_suffix_and_kid(self):
        r = ring()
        keys = {
            r.derive("k1", "field"),
            r.derive("k1", "seal"),
            r.derive("k1", "sign"),
            r.derive("k1", "blind", "a"),
            r.derive("k1", "blind", "b"),
            r.derive("k2", "field"),
        }
        self.assertEqual(len(keys), 6)

    def test_overlong_context_is_rejected(self):
        ring().derive("k1", "blind", "x" * 900)
        with self.assertRaises(ValueError):
            ring().derive("k1", "blind", "x" * 1100)

    def test_unknown_kid(self):
        with self.assertRaises(UnknownKeyError):
            ring().derive("nope", "field")


if __name__ == "__main__":
    unittest.main()
