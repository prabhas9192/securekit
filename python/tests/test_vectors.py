import json
import os
import tempfile
import unittest

from securekit import (
    BlindIndexer, FieldCipher, InvalidToken, Keyring, RecordSealer, Signer,
    context, normalize_text, verify_password,
)
from securekit._encoding import b64u_decode, b64u_encode
from securekit.errors import SecretNotFoundError, WrongPassphraseError
from securekit.uservault import UserVault
from securekit.vault import Vault
from tests.helpers import record_from_triples

PATH = os.path.join(os.path.dirname(__file__), "..", "..", "vectors", "vectors.json")
FROM_NODE = os.path.join(os.path.dirname(__file__), "..", "..", "vectors", "from-node.json")


class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(PATH, encoding="utf-8") as f:
            cls.v = json.load(f)
        cls.ring = Keyring.from_json(json.dumps(cls.v["keyring"]))

    def test_subkeys(self):
        for case in self.v["subkeys"]:
            self.assertEqual(self.ring.derive(case["kid"], case["purpose"], case["suffix"]).hex(), case["hex"])

    def test_context(self):
        for case in self.v["context"]:
            self.assertEqual(context(*case["parts"]), case["expected"])

    def test_normalize(self):
        for case in self.v["normalize"]:
            self.assertEqual(normalize_text(case["input"]), case["expected"], case["input"])

    def test_base64url(self):
        for case in self.v["b64u"]:
            if case["valid"]:
                self.assertEqual(b64u_encode(bytes.fromhex(case["hex"])), case["encoded"])
                self.assertEqual(b64u_decode(case["encoded"]).hex(), case["hex"])
            else:
                with self.assertRaises(ValueError, msg=case["encoded"]):
                    b64u_decode(case["encoded"])

    def test_blind_indexes(self):
        for case in self.v["blind"]:
            indexer = BlindIndexer(self.ring, length_bytes=case["length"])
            self.assertEqual(indexer.candidates(case["value"], case["context"], mode=case["mode"]), case["candidates"])

    def test_seals(self):
        sealer = RecordSealer(self.ring)
        for case in self.v["seal"]:
            record = record_from_triples(case["record"])
            self.assertEqual(sealer.seal(record, case["context"], exclude=case["exclude"]), case["seal"], case["name"])
            self.assertTrue(sealer.verify(record, case["context"], case["seal"], exclude=case["exclude"]), case["name"])

    def test_signatures(self):
        signer = Signer(self.ring)
        for case in self.v["sign"]:
            body = bytes.fromhex(case["body_hex"])
            self.assertEqual(signer.sign(body, timestamp=case["timestamp"]), case["header"])
            self.assertTrue(signer.verify(body, case["header"], now=case["timestamp"]))

    def test_encrypted_fields(self):
        cipher = FieldCipher(self.ring)
        for case in self.v["fields"]:
            self.assertEqual(cipher.decrypt(case["token"], case["context"]).hex(), case["plaintext_hex"])
        for case in self.v["fields_invalid"]:
            with self.assertRaises(InvalidToken, msg=case["why"]):
                cipher.decrypt(case["token"], case["context"])

    def test_password_hashes(self):
        for case in self.v["passwords"]:
            self.assertTrue(verify_password(case["password"], case["hash"]))
            for other in case["also_valid"]:
                self.assertTrue(verify_password(other, case["hash"]), other)
            for other in case["invalid"]:
                self.assertFalse(verify_password(other, case["hash"]), other)
            for bad_hash in case["invalid_hashes"]:
                self.assertFalse(verify_password(case["password"], bad_hash), bad_hash)

    def check_vault_file(self, file_object, active, destroyed):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "vault.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(file_object, handle)
            vault = Vault.open(path, self.ring, clock=lambda: 1_700_000_100)
            vault.verify(deep=True)
            for item in active:
                self.assertEqual(vault.get(item["name"], version=item["version"]).hex(), item["value_hex"], item["name"])
            for item in destroyed:
                with self.assertRaises(SecretNotFoundError):
                    vault.get(item["name"], version=item["version"])
            vault.put("written/by-python", "x")          # a vault from the other implementation can be extended here
            vault.verify(deep=True)

    def check_user_vault(self, case):
        for passphrase in [case["passphrase"], *case.get("also_valid_passphrases", [])]:
            unlocked = UserVault.unlock(case["user_id"], case["state"], passphrase)
            for item in case["items"]:
                self.assertEqual(unlocked.decrypt_item(item["item_id"], item["token"]).hex(), item["plaintext_hex"])
        for passphrase in case.get("wrong_passphrases", []):
            with self.assertRaises(WrongPassphraseError):
                UserVault.unlock(case["user_id"], case["state"], passphrase)
        recovered = UserVault.unlock_with_recovery(case["user_id"], case["state"], case["recovery_key"])
        self.assertEqual(recovered.decrypt_item(case["items"][0]["item_id"], case["items"][0]["token"]).hex(), case["items"][0]["plaintext_hex"])

    def test_vault_file_and_user_vault_state(self):
        vault = self.v["vault"]
        self.check_vault_file(vault["file"], vault["active"], vault["destroyed"])
        self.assertEqual([e["action"] for e in vault["file"]["audit"]], vault["audit_actions"])
        self.check_user_vault(self.v["uservault"])

    @unittest.skipUnless(os.path.exists(FROM_NODE), "run `npm run emit-vectors` in securekit/node to produce vectors/from-node.json")
    def test_vault_and_user_vault_written_by_node(self):
        with open(FROM_NODE, encoding="utf-8") as f:
            node = json.load(f)
        self.check_vault_file(node["vault"]["file"], node["vault"]["active"], node["vault"]["destroyed"])
        self.check_user_vault(node["uservault"])

    @unittest.skipUnless(os.path.exists(FROM_NODE), "run `npm run emit-vectors` in securekit/node to produce vectors/from-node.json")
    def test_tokens_written_by_node_are_readable_here(self):
        with open(FROM_NODE, encoding="utf-8") as f:
            node = json.load(f)
        cipher = FieldCipher(self.ring)
        for case in node["fields"]:
            self.assertEqual(cipher.decrypt(case["token"], case["context"]).hex(), case["plaintext_hex"])
        for case in node["passwords"]:
            self.assertTrue(verify_password(case["password"], case["hash"]))


if __name__ == "__main__":
    unittest.main()
