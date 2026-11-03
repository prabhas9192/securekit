import json
import unittest

from securekit import InvalidToken
from securekit.errors import SecureKitError, WrongPassphraseError
from securekit.uservault import UserVault

PASSPHRASE = "correct horse battery staple"


class UserVaultTests(unittest.TestCase):
    def test_round_trip_and_state_holds_no_plaintext_key(self):
        vault, recovery = UserVault.create("user-42", PASSPHRASE)
        self.assertIsNone(recovery)
        token = vault.encrypt_item("note-1", "my private note")
        state = json.loads(json.dumps(vault.state))              # it really is JSON-serializable
        self.assertEqual(set(state), {"format", "kdf", "wrapped_key", "recovery_wrapped_key"})
        self.assertEqual(state["kdf"]["m"], 65536)

        again = UserVault.unlock("user-42", state, PASSPHRASE)
        self.assertEqual(again.decrypt_item_str("note-1", token), "my private note")

    def test_wrong_passphrase_wrong_user_and_tampered_state(self):
        vault, _ = UserVault.create("user-42", PASSPHRASE)
        state = vault.state
        with self.assertRaises(WrongPassphraseError):
            UserVault.unlock("user-42", state, "not the passphrase")
        with self.assertRaises(WrongPassphraseError):
            UserVault.unlock("user-43", state, PASSPHRASE)           # state belongs to someone else
        for change in (
            lambda s: s.__setitem__("wrapped_key", s["wrapped_key"][:-3] + "AAA"),
            lambda s: s["kdf"].__setitem__("salt", "AAAAAAAAAAAAAAAAAAAAAA"),
        ):
            broken = vault.state
            change(broken)
            with self.assertRaises(WrongPassphraseError):
                UserVault.unlock("user-42", broken, PASSPHRASE)

    def test_hostile_state_cannot_demand_unbounded_work_or_crash(self):
        state = UserVault.create("u", PASSPHRASE)[0].state
        for mutate in (
            lambda s: s["kdf"].__setitem__("m", 4_194_304),
            lambda s: s["kdf"].__setitem__("t", 11),
            lambda s: s["kdf"].__setitem__("p", 17),
            lambda s: s["kdf"].__setitem__("alg", "argon2i"),
            lambda s: s["kdf"].__setitem__("m", True),
            lambda s: s["kdf"].__setitem__("salt", "AA"),
            lambda s: s.__setitem__("format", "x"),
            lambda s: s.__setitem__("wrapped_key", 5),
            lambda s: s.__setitem__("recovery_wrapped_key", 5),
            lambda s: s["kdf"].__delitem__("salt"),
        ):
            broken = UserVault.create("u", PASSPHRASE)[0].state if False else json.loads(json.dumps(state))
            mutate(broken)
            with self.subTest(mutation=broken["kdf"]):
                with self.assertRaises(SecureKitError):
                    UserVault.unlock("u", broken, PASSPHRASE)
        for bad in (None, [], "x", {}):
            with self.assertRaises(SecureKitError):
                UserVault.unlock("u", bad, PASSPHRASE)

    def test_items_are_bound_to_user_and_item(self):
        vault, _ = UserVault.create("alice", PASSPHRASE)
        token = vault.encrypt_item("note-1", "secret")
        with self.assertRaises(InvalidToken):
            vault.decrypt_item("note-2", token)
        other, _ = UserVault.create("bob", PASSPHRASE)
        with self.assertRaises(InvalidToken):
            other.decrypt_item("note-1", token)

    def test_changing_the_passphrase_keeps_items_and_invalidates_the_old_one(self):
        vault, _ = UserVault.create("u", PASSPHRASE)
        token = vault.encrypt_item("n", "data")
        old_state = vault.state
        new_state = vault.change_passphrase("a brand new passphrase")
        self.assertNotEqual(new_state["kdf"]["salt"], old_state["kdf"]["salt"])
        self.assertEqual(UserVault.unlock("u", new_state, "a brand new passphrase").decrypt_item_str("n", token), "data")
        with self.assertRaises(WrongPassphraseError):
            UserVault.unlock("u", new_state, PASSPHRASE)

    def test_recovery_key(self):
        vault, recovery = UserVault.create("u", PASSPHRASE, with_recovery=True)
        token = vault.encrypt_item("n", "data")
        state = vault.state
        recovered = UserVault.unlock_with_recovery("u", state, recovery)
        self.assertEqual(recovered.decrypt_item_str("n", token), "data")
        with self.assertRaises(WrongPassphraseError):
            UserVault.unlock_with_recovery("u", state, "A" * 43)
        with self.assertRaises(WrongPassphraseError):
            UserVault.unlock_with_recovery("u", state, "not a key")

        no_recovery, _ = UserVault.create("u", PASSPHRASE)
        with self.assertRaises(SecureKitError):
            UserVault.unlock_with_recovery("u", no_recovery.state, recovery)

        # recovering lets the user choose a new passphrase; a replaced recovery key retires the old one
        recovered.change_passphrase("recovered and renewed")
        fresh = recovered.new_recovery_key()
        self.assertNotEqual(fresh, recovery)
        with self.assertRaises(WrongPassphraseError):
            UserVault.unlock_with_recovery("u", recovered.state, recovery)
        self.assertEqual(UserVault.unlock_with_recovery("u", recovered.state, fresh).decrypt_item_str("n", token), "data")

    def test_passphrase_rules_and_unicode_equivalence(self):
        with self.assertRaises(ValueError):
            UserVault.create("u", "short")
        with self.assertRaises(TypeError):
            UserVault.create("u", b"not a string passphrase")
        vault, _ = UserVault.create("u", "pässwörd long")
        UserVault.unlock("u", vault.state, "pässwörd long")       # decomposed form of the same passphrase
        with self.assertRaises(ValueError):
            UserVault.unlock("u", vault.state, "x" * 5000)


if __name__ == "__main__":
    unittest.main()
