import unittest
import uuid
from typing import Optional

try:
    from sqlalchemy import Integer, String, create_engine, insert, select, update
    from sqlalchemy.orm import DeclarativeBase, Mapped, Session, load_only, mapped_column
except ImportError:  # the ORM integration is optional
    raise unittest.SkipTest("sqlalchemy is not installed")

from securekit import InvalidToken, SecureKitError
from securekit.errors import TamperedRowError
from securekit.orm import EncryptedText, SealSpec, SecureModels
from tests.helpers import ring


def make_models(keyring, *, role_default=False, assign_id=True, seal_fields=("id", "role", "balance", "password_hash")):
    """A fresh declarative Base, User model and SecureModels bound to `keyring`."""

    class Base(DeclarativeBase):
        pass

    class User(Base):
        __tablename__ = "users"
        id: Mapped[str] = mapped_column(String(36), primary_key=True)
        email: Mapped[Optional[str]] = mapped_column(EncryptedText)
        email_idx: Mapped[Optional[str]] = mapped_column(String(100), index=True)
        ssn: Mapped[Optional[str]] = mapped_column(EncryptedText)
        role: Mapped[Optional[str]] = mapped_column(String(20), default="user") if role_default else mapped_column(String(20))
        balance: Mapped[Optional[int]] = mapped_column(Integer)
        password_hash: Mapped[Optional[str]] = mapped_column(String(200))
        nickname: Mapped[Optional[str]] = mapped_column(String(50))
        row_seal: Mapped[Optional[str]] = mapped_column(String(200))

    secure = SecureModels(keyring)
    secure.register(
        User,
        encrypted=["email", "ssn"],
        blind={"email_idx": "email"},
        seal=SealSpec("row_seal", list(seal_fields)),
        assign_id=(lambda: str(uuid.uuid4())) if assign_id else None,
    )
    return Base, User, secure


class OrmTests(unittest.TestCase):
    def _new_engine(self):
        engine = create_engine("sqlite://")
        self.addCleanup(engine.dispose)
        return engine

    def setUp(self):
        self.engine = self._new_engine()
        self.Base, self.User, self.secure = make_models(ring())
        self.Base.metadata.create_all(self.engine)

    def raw(self, sql, params=()):
        with self.engine.begin() as connection:
            result = connection.exec_driver_sql(sql, params)
            return result.fetchall() if result.returns_rows else None

    def add_user(self, **overrides):
        values = dict(email="Alice@Example.com", ssn="123-45-6789", role="user", balance=10, password_hash="$argon2id$x")
        values.update(overrides)
        with Session(self.engine) as session:
            user = self.User(**values)
            session.add(user)
            session.commit()
            return user.id

    # -------------------------------------------------------------- encryption

    def test_round_trip_and_nothing_readable_in_the_database(self):
        uid = self.add_user()
        email, ssn, idx, seal = self.raw("select email, ssn, email_idx, row_seal from users")[0]
        self.assertTrue(email.startswith("sk1.k2.") and ssn.startswith("sk1.k2."))
        self.assertNotIn("Alice", email)
        self.assertNotIn("123-45", ssn)
        self.assertTrue(idx.startswith("k2.") and seal.startswith("sk1s.k2."))

        with Session(self.engine) as session:
            user = session.get(self.User, uid)
            self.assertEqual((user.email, user.ssn), ("Alice@Example.com", "123-45-6789"))

    def test_plaintext_stays_on_the_instance_across_flush_and_commit(self):
        with Session(self.engine, expire_on_commit=False) as session:
            user = self.User(email="a@x.com", ssn="1", role="user", balance=1, password_hash="h")
            session.add(user)
            session.flush()
            self.assertEqual(user.email, "a@x.com")
            session.commit()
            self.assertEqual((user.email, user.ssn), ("a@x.com", "1"))
        with Session(self.engine) as session:  # default expire_on_commit: reloads and decrypts
            user = session.get(self.User, user.id)
            session.commit()
            self.assertEqual(user.email, "a@x.com")
            session.refresh(user)
            self.assertEqual(user.ssn, "1")

    def test_updates_only_rewrite_what_changed(self):
        uid = self.add_user()
        ssn_before, idx_before = self.raw("select ssn, email_idx from users")[0]
        with Session(self.engine) as session:
            user = session.get(self.User, uid)
            user.role = "admin"
            session.commit()
        ssn_after, idx_after = self.raw("select ssn, email_idx from users")[0]
        self.assertEqual((ssn_after, idx_after), (ssn_before, idx_before))

        with Session(self.engine) as session:
            user = session.get(self.User, uid)
            user.email = "new@example.com"
            session.commit()
        email, idx, ssn_final = self.raw("select email, email_idx, ssn from users")[0]
        self.assertNotEqual(idx, idx_before)
        self.assertEqual(ssn_final, ssn_before)
        with Session(self.engine) as session:
            self.assertEqual(session.get(self.User, uid).email, "new@example.com")

    def test_null_stays_null_and_can_be_set_later(self):
        uid = self.add_user(ssn=None, email=None)
        self.assertEqual(self.raw("select ssn, email, email_idx from users")[0], (None, None, None))
        with Session(self.engine) as session:
            user = session.get(self.User, uid)
            self.assertIsNone(user.ssn)
            user.ssn = "999"
            session.commit()
        self.assertTrue(self.raw("select ssn from users")[0][0].startswith("sk1.k2."))
        with Session(self.engine) as session:
            self.assertEqual(session.get(self.User, uid).ssn, "999")

    # -------------------------------------------------------------- blind index

    def test_blind_filter_finds_normalized_matches_only(self):
        uid = self.add_user()
        self.add_user(email="bob@example.com", ssn="2")
        with Session(self.engine) as session:
            found = session.scalars(select(self.User).where(self.secure.blind_filter(self.User, "email", "  ALICE@example.com "))).all()
            self.assertEqual([u.id for u in found], [uid])
            self.assertEqual(session.scalars(select(self.User).where(self.secure.blind_filter(self.User, "email", "nobody@example.com"))).all(), [])
        with self.assertRaises(ValueError):
            self.secure.blind_filter(self.User, "ssn", "x")

    # -------------------------------------------------------------- tampering

    def test_ciphertext_copied_to_another_row_is_rejected(self):
        alice = self.add_user()
        bob = self.add_user(email="bob@example.com", ssn="999-99-9999")
        self.raw("update users set ssn = (select ssn from users where id = ?) where id = ?", (alice, bob))
        with Session(self.engine) as session:
            self.assertEqual(session.get(self.User, alice).ssn, "123-45-6789")
            with self.assertRaises(InvalidToken):
                session.get(self.User, bob)

    def test_ciphertext_moved_between_columns_is_rejected(self):
        uid = self.add_user()
        self.raw("update users set email = ssn, ssn = email where id = ?", (uid,))
        with Session(self.engine) as session:
            with self.assertRaises(InvalidToken):
                session.get(self.User, uid)

    def test_sealed_columns_cannot_be_changed_behind_the_applications_back(self):
        uid = self.add_user()
        for column, value in (("balance", 999999), ("role", "'admin'"), ("password_hash", "'$argon2id$attacker'")):
            with self.subTest(column=column):
                self.raw(f"update users set {column} = {value} where id = ?", (uid,))  # securekit-ignore: sql-injection (test helper, constant column names)
                with Session(self.engine) as session:
                    with self.assertRaises(TamperedRowError):
                        session.get(self.User, uid)
                self.raw("delete from users")
                uid = self.add_user()

    def test_a_seal_cannot_be_copied_to_another_row_even_when_the_values_match(self):
        engine = self._new_engine()
        base, user_class, _ = make_models(ring(), seal_fields=("role", "balance", "password_hash"))  # id not sealed
        base.metadata.create_all(engine)
        ids = []
        with Session(engine) as session:
            for email in ("a@x.com", "b@x.com"):
                user = user_class(email=email, role="user", balance=1, password_hash="h")
                session.add(user)
                session.commit()
                ids.append(user.id)
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "update users set row_seal = (select row_seal from users where id = ?) where id = ?", (ids[0], ids[1])
            )
        with Session(engine) as session:
            self.assertEqual(session.get(user_class, ids[0]).email, "a@x.com")
            with self.assertRaises(TamperedRowError):
                session.get(user_class, ids[1])

    def test_unsealed_columns_may_change_freely(self):
        uid = self.add_user()
        self.raw("update users set nickname = 'ally' where id = ?", (uid,))
        with Session(self.engine) as session:
            self.assertEqual(session.get(self.User, uid).nickname, "ally")

    def test_verify_seal_and_partial_loads(self):
        uid = self.add_user()
        with Session(self.engine) as session:
            user = session.get(self.User, uid)
            self.assertTrue(self.secure.verify_seal(user))
            session.expunge_all()
            with self.assertRaises(SecureKitError):  # sealed columns missing: refuse rather than skip verification
                session.scalars(select(self.User).options(load_only(self.User.email))).all()

    def test_modifying_an_expired_object_keeps_the_seal_valid(self):
        uid = self.add_user()
        with Session(self.engine) as session:
            user = session.get(self.User, uid)
            session.commit()  # expires everything
            user.role = "admin"
            session.commit()
        with Session(self.engine) as session:
            user = session.get(self.User, uid)
            self.assertEqual(user.role, "admin")
            self.assertTrue(self.secure.verify_seal(user))

    def test_an_expired_update_does_not_launder_a_tampered_column(self):
        uid = self.add_user()
        with Session(self.engine) as session:
            user = session.get(self.User, uid)
            session.commit()  # expires everything, so the next flush has to read the stored row
            self.raw("update users set balance = 999999 where id = ?", (uid,))
            user.role = "admin"
            with self.assertRaises(TamperedRowError):
                session.commit()
        # the stored seal was not replaced by one that blesses the tampered value
        with Session(self.engine) as session:
            with self.assertRaises(TamperedRowError):
                session.get(self.User, uid)

    def test_partial_refresh_with_pending_changes_is_not_a_false_alarm(self):
        uid = self.add_user()
        with Session(self.engine) as session:
            user = session.get(self.User, uid)
            user.balance = 50                       # pending, not flushed
            session.refresh(user, ["nickname"])     # partial refresh of an unsealed column
            session.commit()
        with Session(self.engine) as session:
            self.assertEqual(session.get(self.User, uid).balance, 50)

    # -------------------------------------------------------------- failing closed

    def test_plaintext_cannot_reach_an_encrypted_column_any_other_way(self):
        table = self.User.__table__
        with self.assertRaises(Exception) as caught:
            with self.engine.begin() as connection:
                connection.execute(insert(table).values(id="x", email="plain@example.com"))
        self.assertIn("EncryptedText", str(caught.exception))
        uid = self.add_user()
        with self.assertRaises(Exception) as caught:
            with self.engine.begin() as connection:
                connection.execute(update(table).where(table.c.id == uid).values(ssn="000"))
        self.assertIn("EncryptedText", str(caught.exception))

    def test_filtering_on_an_encrypted_column_is_refused(self):
        self.add_user()
        with Session(self.engine) as session:
            with self.assertRaises(Exception) as caught:
                session.scalars(select(self.User).where(self.User.email == "Alice@Example.com")).all()
            self.assertIn("EncryptedText", str(caught.exception))

    def test_a_missing_primary_key_is_an_error_not_a_weaker_ciphertext(self):
        _, user_class, _ = make_models(ring(), assign_id=False)
        engine = self._new_engine()
        user_class.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(user_class(email="a@x.com", role="user", balance=1))
            with self.assertRaises(SecureKitError) as caught:
                session.flush()
            self.assertIn("primary key", str(caught.exception))

    def test_autoincrement_keys_are_refused(self):
        class Base(DeclarativeBase):
            pass

        class Note(Base):
            __tablename__ = "notes"
            id: Mapped[int] = mapped_column(Integer, primary_key=True)
            body: Mapped[Optional[str]] = mapped_column(EncryptedText)

        SecureModels(ring()).register(Note, encrypted=["body"])
        engine = self._new_engine()
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(Note(body="secret"))
            with self.assertRaises(SecureKitError):
                session.flush()

    def test_sealed_column_defaults_are_rejected_instead_of_silently_mismatching(self):
        engine = self._new_engine()
        base, user_class, _ = make_models(ring(), role_default=True)
        base.metadata.create_all(engine)
        with Session(engine) as session:
            session.add(user_class(email="a@x.com", balance=1, password_hash="h"))  # role left to its default
            with self.assertRaises(SecureKitError) as caught:
                session.flush()
            self.assertIn("default", str(caught.exception))

    def test_non_text_values_are_rejected(self):
        with Session(self.engine) as session:
            session.add(self.User(email="a@x.com", ssn=123, role="user", balance=1, password_hash="h"))
            with self.assertRaises(TypeError):
                session.flush()

    def test_registration_is_validated(self):
        _, user_class, secure = make_models(ring())
        other = SecureModels(ring())
        with self.assertRaises(ValueError):
            other.register(user_class, encrypted=["nickname"])        # not an EncryptedText column
        with self.assertRaises(ValueError):
            other.register(user_class, encrypted=["nope"])
        with self.assertRaises(ValueError):
            other.register(user_class, encrypted=["email"], seal=SealSpec("row_seal", ["email"]))
        with self.assertRaises(ValueError):
            other.register(user_class, blind={"ssn": "email"})        # index column cannot be EncryptedText
        with self.assertRaises(SecureKitError):
            other.blind_filter(int, "x", "y")

    # -------------------------------------------------------------- rotation

    def test_rotation_rewrites_everything_under_the_new_primary_key(self):
        old_ring = ring(primary="k1", kids=("k1",))
        engine = self._new_engine()
        old_base, old_user, _ = make_models(old_ring)
        old_base.metadata.create_all(engine)
        with Session(engine) as session:
            user = old_user(email="Alice@Example.com", ssn="123", role="user", balance=5, password_hash="h")
            session.add(user)
            session.commit()
            uid = user.id

        new_base, new_user, secure = make_models(ring(primary="k2", kids=("k1", "k2")))
        with Session(engine) as session:
            # searching still works while rows are on the old key
            found = session.scalars(select(new_user).where(secure.blind_filter(new_user, "email", "alice@example.com"))).all()
            self.assertEqual([u.id for u in found], [uid])
            user = found[0]
            self.assertEqual(user.ssn, "123")
            self.assertTrue(secure.needs_rotation(user))
            secure.mark_for_rotation(user)
            session.commit()

        with engine.connect() as connection:
            email, ssn, idx, seal = connection.exec_driver_sql("select email, ssn, email_idx, row_seal from users").fetchone()
        self.assertTrue(email.startswith("sk1.k2.") and ssn.startswith("sk1.k2."))
        self.assertTrue(idx.startswith("k2.") and seal.startswith("sk1s.k2."))
        with Session(engine) as session:
            user = session.get(new_user, uid)
            self.assertEqual((user.email, user.ssn), ("Alice@Example.com", "123"))
            self.assertFalse(secure.needs_rotation(user))

        # once k1 is retired the rotated row still reads
        _, retired_user, _ = make_models(ring(primary="k2", kids=("k2",)))
        with Session(engine) as session:
            self.assertEqual(session.get(retired_user, uid).email, "Alice@Example.com")

    def test_paged_rotation_loop_from_the_readme(self):
        engine = self._new_engine()
        old_base, old_user, _ = make_models(ring(primary="k1", kids=("k1",)))
        old_base.metadata.create_all(engine)
        with Session(engine) as session:
            for n in range(5):
                session.add(old_user(email=f"user{n}@example.com", ssn=str(n), role="user", balance=n, password_hash="h"))
            session.commit()

        _, user_class, secure = make_models(ring(primary="k2", kids=("k1", "k2")))
        rotated, last = 0, ""
        with Session(engine) as session:
            while True:
                page = session.scalars(select(user_class).where(user_class.id > last).order_by(user_class.id).limit(2)).all()
                if not page:
                    break
                last = page[-1].id
                for user in page:
                    if secure.needs_rotation(user):
                        secure.mark_for_rotation(user)
                        rotated += 1
                session.commit()
        self.assertEqual(rotated, 5)
        with engine.connect() as connection:
            rows = connection.exec_driver_sql("select email, ssn, email_idx, row_seal from users").fetchall()
        for email, ssn, idx, seal in rows:
            self.assertTrue(email.startswith("sk1.k2.") and ssn.startswith("sk1.k2.") and idx.startswith("k2.") and seal.startswith("sk1s.k2."))
        with Session(engine) as session:
            self.assertEqual(sorted(u.email for u in session.scalars(select(user_class))), [f"user{n}@example.com" for n in range(5)])

    def test_rows_on_the_current_key_are_not_flagged(self):
        uid = self.add_user()
        with Session(self.engine) as session:
            self.assertFalse(self.secure.needs_rotation(session.get(self.User, uid)))

    def test_deleting_works(self):
        uid = self.add_user()
        with Session(self.engine) as session:
            session.delete(session.get(self.User, uid))
            session.commit()
        self.assertEqual(self.raw("select count(*) from users")[0][0], 0)


if __name__ == "__main__":
    unittest.main()
