import unittest

from securekit import BlindIndexer, RecordSealer, Signer, context, normalize_text
from tests.helpers import ring

EMAIL = context("users", "email")


class BlindIndexTests(unittest.TestCase):
    def setUp(self):
        self.blind = BlindIndexer(ring())

    def test_normalization_makes_equivalent_spellings_match(self):
        base = self.blind.index("alice@example.com", EMAIL)
        for variant in ("Alice@Example.COM", "  alice@example.com\n", "ＡＬＩＣＥ＠ｅｘａｍｐｌｅ．ｃｏｍ", " alice@example.com　"):
            with self.subTest(variant=variant):
                self.assertEqual(self.blind.index(variant, EMAIL), base)
        self.assertNotEqual(self.blind.index("bob@example.com", EMAIL), base)

    def test_normalization_rules(self):
        self.assertEqual(normalize_text("é"), "é")        # NFKC composes
        self.assertEqual(normalize_text("É"), "É")         # only ASCII is lowercased
        self.assertEqual(normalize_text("K"), "k")              # Kelvin sign: NFKC first, then lower
        self.assertEqual(normalize_text("ﬁ"), "fi")             # ligature
        self.assertEqual(normalize_text("x "), "x")
        self.assertEqual(normalize_text("﻿a"), "﻿a")       # BOM is not whitespace here

    def test_column_context_separates_indexes(self):
        self.assertNotEqual(
            self.blind.index("alice@example.com", context("users", "email")),
            self.blind.index("alice@example.com", context("users", "recovery_email")),
        )

    def test_exact_mode_and_length(self):
        self.assertNotEqual(self.blind.index("Alice", EMAIL, mode="exact"), self.blind.index("alice", EMAIL, mode="exact"))
        short = BlindIndexer(ring(), length_bytes=8).index("x", EMAIL)
        self.assertEqual(len(short.split(".")[1]), 16)
        self.assertEqual(len(self.blind.index("x", EMAIL).split(".")[1]), 32)
        with self.assertRaises(ValueError):
            BlindIndexer(ring(), length_bytes=3)

    def test_candidates_cover_every_key(self):
        candidates = self.blind.candidates("alice@example.com", EMAIL)
        self.assertEqual([c.split(".")[0] for c in candidates], ["k1", "k2"])
        self.assertIn(self.blind.index("alice@example.com", EMAIL), candidates)
        # a row indexed before the rotation is still found
        before = BlindIndexer(ring(primary="k1", kids=("k1",))).index("alice@example.com", EMAIL)
        self.assertIn(before, candidates)

    def test_argument_checks(self):
        with self.assertRaises(TypeError):
            self.blind.index(None, EMAIL)
        with self.assertRaises(ValueError):
            self.blind.index("x", "")
        with self.assertRaises(ValueError):
            self.blind.index("x", EMAIL, mode="loose")


class RecordSealTests(unittest.TestCase):
    def setUp(self):
        self.sealer = RecordSealer(ring())
        self.record = {"id": 42, "email_index": "k2.ab", "password_hash": "$argon2id$original", "active": True, "note": None}
        self.ctx = context("users", 42)

    def test_round_trip_and_key_order_irrelevant(self):
        seal = self.sealer.seal(self.record, self.ctx)
        self.assertTrue(seal.startswith("sk1s.k2."))
        self.assertTrue(self.sealer.verify(dict(reversed(list(self.record.items()))), self.ctx, seal))

    def test_every_field_is_covered_including_hash_columns(self):
        seal = self.sealer.seal(self.record, self.ctx)
        for key in self.record:
            changed = dict(self.record, **{key: "tampered"})
            with self.subTest(key=key):
                self.assertFalse(self.sealer.verify(changed, self.ctx, seal))

    def test_missing_extra_and_context_changes_break_the_seal(self):
        seal = self.sealer.seal(self.record, self.ctx)
        self.assertFalse(self.sealer.verify({k: v for k, v in self.record.items() if k != "note"}, self.ctx, seal))
        self.assertFalse(self.sealer.verify(dict(self.record, extra="x"), self.ctx, seal))
        self.assertFalse(self.sealer.verify(self.record, context("users", 43), seal))

    def test_types_are_not_interchangeable(self):
        seals = {
            self.sealer.seal({"v": value}, "c")
            for value in ("1", 1, True, b"1", None, "")
        }
        self.assertEqual(len(seals), 6)

    def test_exclude_names_the_seal_column_explicitly(self):
        seal = self.sealer.seal(self.record, self.ctx)
        stored = dict(self.record, row_seal=seal)
        self.assertTrue(self.sealer.verify(stored, self.ctx, seal, exclude=["row_seal"]))
        self.assertFalse(self.sealer.verify(stored, self.ctx, seal))

    def test_unsupported_values_are_rejected(self):
        for value in (1.5, [1], {"a": 1}, object()):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    self.sealer.seal({"v": value}, "c")
        with self.assertRaises(ValueError):
            self.sealer.seal(self.record, "")

    def test_malformed_seals_verify_false(self):
        good = self.sealer.seal(self.record, self.ctx)
        for bad in ("", "sk1s", "sk1s.k2", "sk1s.k2.", "sk1s.k9." + good.split(".")[2], good + "A", good[:-1], None, 7):
            with self.subTest(bad=bad):
                self.assertFalse(self.sealer.verify(self.record, self.ctx, bad))

    def test_old_key_seals_still_verify_after_rotation(self):
        old = RecordSealer(ring(primary="k1", kids=("k1",))).seal(self.record, self.ctx)
        self.assertTrue(self.sealer.verify(self.record, self.ctx, old))


class SignerTests(unittest.TestCase):
    def setUp(self):
        self.signer = Signer(ring())
        self.now = 1_700_000_000

    def test_round_trip_for_text_and_bytes(self):
        for body in ('{"event":"paid"}', "héllo", b"\x00\xff"):
            with self.subTest(body=body):
                header = self.signer.sign(body, timestamp=self.now)
                self.assertTrue(header.startswith(f"t={self.now},kid=k2,v1="))
                self.assertTrue(self.signer.verify(body, header, now=self.now + 10))

    def test_tampering_is_rejected(self):
        header = self.signer.sign("body", timestamp=self.now)
        self.assertFalse(self.signer.verify("body!", header, now=self.now))
        self.assertFalse(self.signer.verify("body", header.replace(f"t={self.now}", f"t={self.now + 1}"), now=self.now))
        self.assertFalse(self.signer.verify("body", header[:-1] + ("0" if header[-1] != "0" else "1"), now=self.now))

    def test_replay_window_both_directions(self):
        header = self.signer.sign("body", timestamp=self.now)
        self.assertTrue(self.signer.verify("body", header, now=self.now + 300))
        self.assertFalse(self.signer.verify("body", header, now=self.now + 301))
        self.assertTrue(self.signer.verify("body", header, now=self.now - 300))
        self.assertFalse(self.signer.verify("body", header, now=self.now - 301))
        self.assertTrue(self.signer.verify("body", header, tolerance_seconds=1000, now=self.now + 1000))

    def test_malformed_headers_are_false_not_errors(self):
        good = self.signer.sign("body", timestamp=self.now)
        mac = good.rsplit("=", 1)[1]
        for bad in (
            "", "t=1", f"t={self.now},kid=k2", f"t={self.now},kid=k2,v1={mac},v1={mac}", f"t={self.now},kid=k2,v1={mac},x=1",
            f"t=abc,kid=k2,v1={mac}", f"t={self.now},kid=k9,v1={mac}", f"t={self.now},kid=k2,v1={mac.upper()}",
            f"t={self.now},kid=k2,v1={mac[:-2]}", f"t=-1,kid=k2,v1={mac}", f"t=1{self.now}0000,kid=k2,v1={mac}", None, 5,
        ):
            with self.subTest(bad=bad):
                self.assertFalse(self.signer.verify("body", bad, now=self.now))

    def test_old_key_signatures_verify_after_rotation(self):
        old = Signer(ring(primary="k1", kids=("k1",))).sign("body", timestamp=self.now)
        self.assertTrue(self.signer.verify("body", old, now=self.now))

    def test_sign_validates_timestamp(self):
        for bad in (-1, 1.5, True, 10**12):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.signer.sign("body", timestamp=bad)


if __name__ == "__main__":
    unittest.main()
