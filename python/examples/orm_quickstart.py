"""
SQLAlchemy quickstart. Needs `pip install sqlalchemy`. Run from securekit/python:  python examples/orm_quickstart.py
"""

import os
import sys
import uuid
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from sqlalchemy import Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from securekit import InvalidToken, Keyring, generate_key
from securekit.errors import TamperedRowError
from securekit.orm import EncryptedText, SealSpec, SecureModels


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(EncryptedText)                        # ciphertext at rest
    email_idx: Mapped[Optional[str]] = mapped_column(String(100), index=True)  # blind index, maintained for you
    ssn: Mapped[Optional[str]] = mapped_column(EncryptedText)
    role: Mapped[str] = mapped_column(String(20))
    balance: Mapped[int] = mapped_column(Integer)
    row_seal: Mapped[Optional[str]] = mapped_column(String(200))             # tamper seal over id, role, balance


keyring = Keyring({"k1": generate_key()}, "k1")  # in a real app: Keyring.from_env()
secure = SecureModels(keyring)
secure.register(
    User,
    encrypted=["email", "ssn"],
    blind={"email_idx": "email"},
    seal=SealSpec("row_seal", ["id", "role", "balance"]),
    assign_id=lambda: str(uuid.uuid4()),  # ids exist before the flush: they are bound into every ciphertext
)

engine = create_engine("sqlite://")
Base.metadata.create_all(engine)

with Session(engine) as session:
    session.add(User(email="Alice@Example.com", ssn="123-45-6789", role="user", balance=10))
    session.commit()

with engine.connect() as connection:
    email, ssn, idx, seal = connection.exec_driver_sql("select email, ssn, email_idx, row_seal from users").one()
    print("in the database :", email[:28] + "...", "|", idx[:12] + "...", "|", seal[:16] + "...")

with Session(engine) as session:
    user = session.scalars(select(User).where(secure.blind_filter(User, "email", "alice@example.com"))).one()
    print("found by search :", user.email, "| ssn:", user.ssn)
    uid = user.id

with engine.begin() as connection:  # someone edits the database directly
    connection.exec_driver_sql("update users set balance = 1000000 where id = ?", (uid,))
try:
    with Session(engine) as session:
        session.get(User, uid)
except TamperedRowError as error:
    print("tampering caught:", error)
engine.dispose()
