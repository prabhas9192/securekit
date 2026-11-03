import unittest

from securekit import FieldCipher, InvalidToken, Keyring, UnknownKeyError, context
from securekit._encoding import b64u_decode
from tests.helpers import KEY_K1, KEY_K2, KEY_K3, ring

CTX = context("users", "ssn", 42)


class FieldCipherTests(unittest.TestCase):
    def setUp(self):
        self.cipher = FieldCipher(ring())

    def test_round_trip_text_bytes_and_empty(self):
        for plaintext in ("123-45-6789", "ünïcödé ✓", "", b"\x00\xff\x10"):
            with self.subTest(plaintext=plaintext):
                token = self.cipher.encrypt(plaintext, CTX)
                expected = plaintext.encode() if isinstance(plaintext, str) else plaintext
                self.assertEqual(self.cipher.decrypt(token, CTX), expected)

    def test_token_shape_and_randomized_nonce(self):
        first, second = self.cipher.encrypt("x", CTX), self.cipher.encrypt("x", CTX)
        self.assertNotEqual(first, second)
        version, kid, body = first.split(".")
        self.assertEqual((version, kid), ("sk1", "k2"))
        self.assertEqual(len(b64u_decode(body)), 12 + 1 + 16)

    def test_context_is_mandatory_and_bound(self):
        with self.assertRaises(ValueError):
            self.cipher.encrypt("x", "")
        token = self.cipher.encrypt("secret", CTX)
        for other in (context("users", "ssn", 43), context("users", "email", 42), "x"):
            with self.subTest(other=other):
                with self.assertRaises(InvalidToken):
                    self.cipher.decrypt(token, other)
        with self.assertRaises(ValueError):
            self.cipher.decrypt(token, "")

    def test_context_encoding_is_unambiguous(self):
        self.assertNotEqual(context("ab", "c"), context("a", "bc"))
        self.assertNotEqual(context("a|1:b"), context("a", "b"))
        self.assertEqual(context("users", "ssn", 42), "5:users|3:ssn|2:42")
        self.assertEqual(context("é"), "2:é")
        with self.assertRaises(TypeError):
            context(True)
        with self.assertRaises(TypeError):
            context(1.5)
        with self.assertRaises(ValueError):
            context()

    def test_every_single_character_change_is_rejected(self):
        token = self.cipher.encrypt("secret", CTX)
        head, body = token.rsplit(".", 1)
        for i, original in enumerate(body):
            replacement = "A" if original != "A" else "B"
            tampered = f"{head}.{body[:i]}{replacement}{body[i + 1:]}"
            with self.subTest(position=i):
                with self.assertRaises(InvalidToken):
                    self.cipher.decrypt(tampered, CTX)

    def test_malformed_tokens_only_raise_invalid_token(self):
        good = self.cipher.encrypt("x", CTX)
        for bad in (
            "", "sk1", "sk1.k2", "sk1.k2.", "sk1.k2.AAAA", "sk1.k2." + "A" * 100, "sk2.k2.xx",
            "a.b.c.d", good + ".", good + "=", good.replace("sk1", "SK1"), None, 5, b"sk1.k2.AAAA",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidToken):
                    self.cipher.decrypt(bad, CTX)

    def test_token_from_another_keyring_is_rejected(self):
        foreign = FieldCipher(Keyring({"k2": KEY_K3}, "k2"))
        with self.assertRaises(InvalidToken):
            self.cipher.decrypt(foreign.encrypt("x", CTX), CTX)

    def test_unknown_key_id(self):
        token = FieldCipher(Keyring({"k9": KEY_K1}, "k9")).encrypt("x", CTX)
        with self.assertRaises(UnknownKeyError):
            self.cipher.decrypt(token, CTX)
        with self.assertRaises(InvalidToken):  # callers may catch the base class
            self.cipher.decrypt(token, CTX)

    def test_key_id_label_is_authenticated(self):
        # Two ring entries holding the same key still cannot swap labels.
        same = Keyring({"a": KEY_K1, "b": KEY_K1}, "a")
        cipher = FieldCipher(same)
        token = cipher.encrypt("x", CTX)
        relabeled = token.replace("sk1.a.", "sk1.b.")
        with self.assertRaises(InvalidToken):
            cipher.decrypt(relabeled, CTX)

    def test_rotation(self):
        old = FieldCipher(Keyring({"k1": KEY_K1}, "k1"))
        token = old.encrypt("secret", CTX)

        rotated_ring = FieldCipher(Keyring({"k1": KEY_K1, "k2": KEY_K2}, "k2"))
        self.assertEqual(rotated_ring.decrypt(token, CTX), b"secret")
        self.assertTrue(rotated_ring.needs_rotation(token))

        fresh = rotated_ring.rotate(token, CTX)
        self.assertTrue(fresh.startswith("sk1.k2."))
        self.assertFalse(rotated_ring.needs_rotation(fresh))
        self.assertEqual(rotated_ring.rotate(fresh, CTX), fresh)
        self.assertEqual(rotated_ring.decrypt(fresh, CTX), b"secret")

        # once k1 is retired, rotated data still reads and unrotated data does not
        retired = FieldCipher(Keyring({"k2": KEY_K2}, "k2"))
        self.assertEqual(retired.decrypt(fresh, CTX), b"secret")
        with self.assertRaises(UnknownKeyError):
            retired.decrypt(token, CTX)

    def test_decrypt_str_rejects_non_utf8(self):
        token = self.cipher.encrypt(b"\xff\xfe", CTX)
        with self.assertRaises(InvalidToken):
            self.cipher.decrypt_str(token, CTX)

    def test_plaintext_type_checked(self):
        with self.assertRaises(TypeError):
            self.cipher.encrypt(123, CTX)


if __name__ == "__main__":
    unittest.main()
