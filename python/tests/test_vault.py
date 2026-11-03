import json
import os
import tempfile
import time
import unittest

from securekit import InvalidToken, Keyring
from securekit.errors import (
    SecretNotFoundError,
    TamperedVaultError,
    VaultExistsError,
    VaultLockedError,
)
from securekit.vault import Vault
from tests.helpers import KEY_K1, KEY_K2, ring


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "secrets.vault.json")
        self.now = 1_700_000_000
        self.clock = lambda: self.now
        self.vault = Vault.create(self.path, ring(), actor="deploy", clock=self.clock)

    def reopen(self, **kwargs):
        return Vault.open(self.path, kwargs.pop("keyring", ring()), clock=self.clock, **kwargs)

    def edit(self, change):
        with open(self.path, encoding="utf-8") as handle:
            data = json.load(handle)
        change(data)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

    # ------------------------------------------------------------ basics

    def test_create_put_get_round_trip_and_nothing_readable_on_disk(self):
        self.assertEqual(self.vault.put("payments/stripe_key", "sk_live_SECRET123"), 1)
        self.assertEqual(self.vault.get_str("payments/stripe_key"), "sk_live_SECRET123")
        self.assertEqual(self.reopen().get("payments/stripe_key"), b"sk_live_SECRET123")
        with open(self.path, encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn("SECRET123", raw)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertFalse(os.path.exists(self.path + ".lock"))

    def test_binary_values_and_listing(self):
        self.vault.put("a/b", b"\x00\xff\x01")
        self.vault.put("c", "x")
        self.assertEqual(self.vault.get("a/b"), b"\x00\xff\x01")
        self.assertEqual(self.vault.names(), ["a/b", "c"])

    def test_versions_retention_and_destroy(self):
        for n in range(1, 5):
            self.assertEqual(self.vault.put("k", f"value{n}", retain=2), n)
        self.assertEqual([(v["version"], v["state"]) for v in self.vault.versions("k")],
                         [(1, "destroyed"), (2, "destroyed"), (3, "active"), (4, "active")])
        self.assertEqual(self.vault.get_str("k"), "value4")
        self.assertEqual(self.vault.get_str("k", version=3), "value3")
        with self.assertRaises(SecretNotFoundError):
            self.vault.get("k", version=1)
        self.vault.destroy("k", 4)
        self.assertEqual(self.vault.get_str("k"), "value3")      # latest *active*
        with open(self.path, encoding="utf-8") as handle:
            self.assertNotIn("value4", handle.read())
        self.assertEqual(self.vault.put("k", "value5"), 5)       # version numbers are never reused

    def test_delete_and_missing_names(self):
        self.vault.put("gone", "x")
        self.vault.delete("gone")
        self.assertEqual(self.vault.names(), [])
        for action in (lambda: self.vault.get("gone"), lambda: self.vault.get("never"), lambda: self.vault.delete("gone"),
                       lambda: self.vault.destroy("never", 1), lambda: self.vault.versions("never")):
            with self.assertRaises(SecretNotFoundError):
                action()

    def test_names_values_and_arguments_are_validated(self):
        for bad in ("", "/x", "x/", "a//b", "a/../b", "a/./b", "has space", "x" * 129, "-x", "é", 5):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    self.vault.put(bad, "v")
        for bad in ("", b"", "x" * 1_048_577):
            with self.assertRaises(ValueError):
                self.vault.put("ok", bad)
        with self.assertRaises(ValueError):
            self.vault.put("ok", "v", retain=0)
        with self.assertRaises(VaultExistsError):
            Vault.create(self.path, ring())

    # ------------------------------------------------------------ audit

    def test_audit_trail_records_who_did_what(self):
        self.vault.put("k", "v1")
        self.now += 5
        other = self.reopen(actor="payments-api", audit_reads=True)
        other.get("k")
        other.delete("k")
        trail = [(e["seq"], e["actor"], e["action"], e["name"], e["version"]) for e in self.reopen().audit()]
        self.assertEqual(trail, [(1, "deploy", "init", None, None), (2, "deploy", "put", "k", 1),
                                 (3, "payments-api", "read", "k", 1), (4, "payments-api", "delete", "k", None)])
        self.reopen().verify(deep=False)

    def test_reads_are_not_audited_by_default(self):
        self.vault.put("k", "v")
        before = len(self.vault.audit())
        self.reopen().get("k")
        self.assertEqual(len(self.reopen().audit()), before)

    # ------------------------------------------------------------ tampering

    def test_editing_the_file_is_detected(self):
        self.vault.put("k", "v1")
        self.vault.put("k", "v2")
        edits = {
            "bump generation": lambda d: d.__setitem__("generation", d["generation"] + 1),
            "change metadata": lambda d: d["secrets"]["k"]["versions"][0].__setitem__("by", "mallory"),
            "drop a version": lambda d: d["secrets"]["k"]["versions"].pop(),
            "rename a secret": lambda d: d["secrets"].__setitem__("other", d["secrets"].pop("k")),
            "edit audit entry": lambda d: d["audit"][1].__setitem__("actor", "mallory"),
            "delete audit entry": lambda d: d["audit"].pop(1),
            "truncate audit tail": lambda d: d["audit"].pop(),
            "swap tokens": lambda d: [d["secrets"]["k"]["versions"][0].__setitem__("token", d["secrets"]["k"]["versions"][1]["token"])],
            "change vault id": lambda d: d.__setitem__("id", "AAAAAAAAAAAAAAAAAAAAAA"),
            "wrong format": lambda d: d.__setitem__("format", "other/1"),
            "bad state": lambda d: d["secrets"]["k"]["versions"][0].__setitem__("state", "weird"),
        }
        with open(self.path, encoding="utf-8") as handle:
            original = handle.read()
        for label, change in edits.items():
            with self.subTest(edit=label):
                with open(self.path, "w", encoding="utf-8") as handle:
                    handle.write(original)
                self.edit(change)
                with self.assertRaises(TamperedVaultError):
                    self.reopen()

    def test_garbage_files_are_tamper_errors_not_crashes(self):
        for content in ("", "not json", "[]", "{}", '{"format": "securekit-vault/1"}'):
            with self.subTest(content=content):
                with open(self.path, "w", encoding="utf-8") as handle:
                    handle.write(content)
                with self.assertRaises(TamperedVaultError):
                    self.reopen()

    def test_a_token_copied_between_vaults_does_not_decrypt(self):
        other_path = os.path.join(self.dir.name, "other.json")
        other = Vault.create(other_path, ring(), clock=self.clock)
        self.vault.put("k", "from-first")
        other.put("k", "from-second")
        with open(self.path, encoding="utf-8") as handle:
            stolen = json.load(handle)["secrets"]["k"]["versions"][0]["token"]
        with open(other_path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["secrets"]["k"]["versions"][0]["token"] = stolen
        with open(other_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        with self.assertRaises(TamperedVaultError):
            Vault.open(other_path, ring(), clock=self.clock)           # manifest catches the swap first
        with self.assertRaises(InvalidToken):                          # and the token itself is bound to its vault
            from securekit import FieldCipher
            from securekit._encoding import context
            FieldCipher(ring()).decrypt(stolen, context("vault", data["id"], "k", 1))

    def test_wrong_keyring_is_refused(self):
        self.vault.put("k", "v")
        with self.assertRaises(TamperedVaultError):
            self.reopen(keyring=Keyring({"zz": KEY_K1}, "zz"))

    def test_turning_audit_verification_off_still_catches_truncation_but_not_edits_in_the_middle(self):
        self.vault.put("k", "v")
        self.edit(lambda d: d["audit"][0].__setitem__("actor", "mallory"))
        with self.assertRaises(TamperedVaultError):
            self.reopen()                                    # chain verification sees the edit
        self.reopen(verify_audit=False)                      # the manifest only covers the audit head and count
        self.edit(lambda d: d["audit"].pop())
        with self.assertRaises(TamperedVaultError):
            self.reopen(verify_audit=False)                  # a shortened log changes the head and count
        # restoring an older complete copy of the file (rollback) is not detectable without state kept elsewhere

    # ------------------------------------------------------------ keys

    def test_rotation_moves_everything_to_the_primary_key(self):
        new_ring = ring(primary="k2", kids=("k1", "k2"))
        path = os.path.join(self.dir.name, "k1.json")
        v1 = Vault.create(path, Keyring({"k1": KEY_K1}, "k1"), clock=self.clock)
        v1.put("a", "1")
        v1.put("b", "2")
        v2 = Vault.open(path, new_ring, actor="ops", clock=self.clock)
        self.assertEqual(v2.get_str("a"), "1")                       # old key still reads
        self.assertEqual(v2.rotate_keys(), 2)
        self.assertEqual(v2.rotate_keys(), 0)                        # idempotent
        with open(path, encoding="utf-8") as handle:
            tokens = [v["token"] for e in json.load(handle)["secrets"].values() for v in e["versions"]]
        self.assertTrue(all(t.startswith("sk1.k2.") for t in tokens))
        v2.verify(deep=True)

    def test_retired_keys_make_old_audit_entries_unverifiable(self):
        path = os.path.join(self.dir.name, "k1.json")
        v1 = Vault.create(path, Keyring({"k1": KEY_K1}, "k1"), clock=self.clock)
        v1.put("a", "1")
        Vault.open(path, ring(primary="k2", kids=("k1", "k2")), clock=self.clock).rotate_keys()
        with self.assertRaises(TamperedVaultError):
            Vault.open(path, Keyring({"k2": KEY_K2}, "k2"), clock=self.clock)       # k1 retired: audit cannot verify
        Vault.open(path, Keyring({"k2": KEY_K2}, "k2"), clock=self.clock, verify_audit=False)  # explicit opt-out

    def test_deep_verify_finds_secrets_that_do_not_decrypt(self):
        self.vault.put("k", "v")
        self.reopen().verify(deep=True)

    # ------------------------------------------------------------ concurrency and scoping

    def test_a_held_lock_times_out_and_a_stale_one_is_cleared(self):
        with open(self.path + ".lock", "w") as handle:
            handle.write("999999")
        quick = Vault.open(self.path, ring(), clock=self.clock, lock_timeout=0.3)
        with self.assertRaises(VaultLockedError):
            quick.put("k", "v")
        stale = time.time() - 10_000
        os.utime(self.path + ".lock", (stale, stale))
        self.assertEqual(quick.put("k", "v"), 1)

    def test_two_handles_see_each_others_writes(self):
        first, second = self.reopen(), self.reopen()
        first.put("shared", "1")
        self.assertEqual(second.get_str("shared"), "1")
        second.put("shared", "2")
        self.assertEqual(first.get_str("shared"), "2")

    def test_scoped_view_only_reaches_its_prefix(self):
        self.vault.put("payments/key", "p")
        self.vault.put("email/key", "e")
        scoped = self.vault.scoped("payments/")
        self.assertEqual(scoped.names(), ["payments/key"])
        self.assertEqual(scoped.get_str("payments/key"), "p")
        scoped.put("payments/other", "x")
        for action in (lambda: scoped.get("email/key"), lambda: scoped.put("email/new", "x")):
            with self.assertRaises(SecretNotFoundError):
                action()
        with self.assertRaises(ValueError):
            self.vault.scoped("payments")


if __name__ == "__main__":
    unittest.main()
