import unittest

from argon2 import PasswordHasher, Type

from securekit import constant_time_equals, hash_password, needs_rehash, random_token, verify_password


class PasswordTests(unittest.TestCase):
    def test_round_trip_and_parameters(self):
        stored = hash_password("correct horse battery staple")
        self.assertTrue(stored.startswith("$argon2id$v=19$m=65536,t=3,p=4$"))
        self.assertTrue(verify_password("correct horse battery staple", stored))
        self.assertFalse(verify_password("Correct horse battery staple", stored))
        self.assertNotEqual(stored, hash_password("correct horse battery staple"))  # random salt
        self.assertFalse(needs_rehash(stored))

    def test_unicode_equivalents_verify(self):
        stored = hash_password("pässwörd")           # composed
        self.assertTrue(verify_password("pässwörd", stored))  # decomposed
        self.assertTrue(verify_password("ｐässwörd", stored))  # fullwidth p, NFKC

    def test_bad_inputs_are_false_or_value_errors(self):
        stored = hash_password("pw")
        for bad in ("", "x", "$argon2id$garbage", "$argon2id$v=19$m=1,t=1,p=1$AAAA$AAAA", None, 7):
            with self.subTest(bad=bad):
                self.assertFalse(verify_password("pw", bad))
        self.assertFalse(verify_password("", stored))
        self.assertFalse(verify_password("x" * 5000, stored))
        with self.assertRaises(ValueError):
            hash_password("")
        with self.assertRaises(ValueError):
            hash_password("x" * 5000)
        with self.assertRaises(TypeError):
            hash_password(b"bytes")

    def test_only_argon2id_is_accepted(self):
        argon2i = PasswordHasher(type=Type.I, time_cost=1, memory_cost=8, parallelism=1).hash("pw")
        self.assertTrue(argon2i.startswith("$argon2i$"))
        self.assertFalse(verify_password("pw", argon2i))

    def test_needs_rehash(self):
        weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("pw")
        self.assertTrue(weak.startswith("$argon2id$"))
        self.assertTrue(verify_password("pw", weak))
        self.assertTrue(needs_rehash(weak))
        self.assertTrue(needs_rehash("not a hash"))


class TokenTests(unittest.TestCase):
    def test_random_tokens(self):
        self.assertNotEqual(random_token(), random_token())
        self.assertGreaterEqual(len(random_token(32)), 43)
        with self.assertRaises(ValueError):
            random_token(8)

    def test_constant_time_equals(self):
        self.assertTrue(constant_time_equals("abc", b"abc"))
        self.assertFalse(constant_time_equals("abc", "abd"))
        self.assertFalse(constant_time_equals("abc", "abcd"))
        self.assertTrue(constant_time_equals("é", "é"))


if __name__ == "__main__":
    unittest.main()
