"""
SQLAlchemy 2.x integration.

    secure = SecureModels(Keyring.from_env())
    secure.register(
        User,
        encrypted=["email", "ssn"],                 # columns declared as EncryptedText
        blind={"email_idx": "email"},               # email_idx is kept up to date, search with blind_filter
        seal=SealSpec("row_seal", ["id", "role", "balance"]),
        assign_id=lambda: str(uuid.uuid4()),        # ids must exist before the flush: they are bound into every ciphertext
    )

How it works. A column type cannot see its row, so it cannot bind the primary key. Instead, mapper events run
around the flush: before the INSERT/UPDATE the plaintext attributes are replaced by tokens bound to
`context(table, column, *primary_key)`, after the flush the plaintext is put back on the instance, and when a row is
loaded the tokens are decrypted. Plaintext never reaches the database layer, the bind parameters or the SQL log.

Fails closed. A ciphertext copied to another row or column raises InvalidToken when the row is loaded. Core
statements and bulk operations that try to write plaintext into an EncryptedText column raise instead of storing it.
Filtering on an encrypted column raises; filter on its blind index (SecureModels.blind_filter).

Limits. Use ORM entities, not column-only queries (`select(User.ssn)` returns ciphertext). If a flush fails, discard
the instances that were part of it. Autoincrement integer keys cannot be used: they do not exist before the INSERT.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from sqlalchemy import event, select
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import attributes
from sqlalchemy.types import Text, TypeDecorator

from ._encoding import context as make_context
from .blind import BlindIndexer
from .errors import SecureKitError, TamperedRowError
from .fields import FieldCipher
from .keys import Keyring
from .seal import RecordSealer

_STASH = "securekit.plaintext"
_KIDS = "securekit.kids"


class _Token(str):
    """Ciphertext on its way to or from the database. Never plaintext."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<securekit encrypted value>"


class EncryptedText(TypeDecorator):
    """
    Column type for ciphertext. Values are encrypted by a model registered with SecureModels; anything
    else (Core inserts, bulk updates, filters) is refused instead of being stored or compared as plaintext.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, _Token):
            return str(value)
        raise TypeError(
            "EncryptedText only accepts values encrypted by a model registered with SecureModels. "
            "Write through the ORM on a registered model, and filter on the blind index column, "
            "never on the encrypted column."
        )

    def process_result_value(self, value, dialect):
        return None if value is None else _Token(value)


@dataclass(frozen=True)
class SealSpec:
    """Seal a row: an HMAC over `fields` plus the primary key, stored in `column`."""

    column: str
    fields: Sequence[str]
    transforms: Mapping[str, Callable[[Any], Any]] = field(default_factory=dict)
    verify_on_load: bool = True


@dataclass
class _Config:
    mapper: Any
    table: str
    pk_keys: List[str]
    encrypted: List[str]
    blind: Dict[str, Tuple[str, str]]  # index attr -> (source attr, mode)
    seal: Optional[SealSpec]
    assign_id: Optional[Callable[[], Any]]


def _changed(state, key: str) -> bool:
    return state.attrs[key].history.has_changes()


def _kid_of(token: Any, position: int) -> Optional[str]:
    """Key id of a dotted securekit token ('<kid>.<hex>' at 0, 'sk1s.<kid>.<mac>' at 1), or None."""
    if isinstance(token, str) and token.count(".") >= position + 1:
        return token.split(".")[position]
    return None


def _part(value: Any) -> Union[int, str]:
    return value if isinstance(value, int) and not isinstance(value, bool) else str(value)


class SecureModels:
    def __init__(self, keyring: Keyring, *, blind_length_bytes: int = 16):
        self._ring = keyring
        self.cipher = FieldCipher(keyring)
        self.indexer = BlindIndexer(keyring, blind_length_bytes)
        self.sealer = RecordSealer(keyring)
        self._configs: Dict[type, _Config] = {}

    # ------------------------------------------------------------------ registration

    def register(
        self,
        model: type,
        *,
        encrypted: Sequence[str] = (),
        blind: Optional[Mapping[str, Union[str, Tuple[str, str]]]] = None,
        seal: Optional[SealSpec] = None,
        assign_id: Optional[Callable[[], Any]] = None,
    ) -> type:
        mapper = sa_inspect(model)
        columns = mapper.columns

        def column(attr: str):
            if attr not in columns:
                raise ValueError(f"{model.__name__}.{attr} is not a mapped column")
            return columns[attr]

        for attr in encrypted:
            if not isinstance(column(attr).type, EncryptedText):
                raise ValueError(f"{model.__name__}.{attr} must be declared with the EncryptedText type")

        blind_map: Dict[str, Tuple[str, str]] = {}
        for index_attr, spec in (blind or {}).items():
            source, mode = spec if isinstance(spec, tuple) else (spec, "text")
            column(source)
            if isinstance(column(index_attr).type, EncryptedText):
                raise ValueError(f"{model.__name__}.{index_attr} is a blind index and must not be EncryptedText")
            blind_map[index_attr] = (source, mode)

        if seal is not None:
            column(seal.column)
            for attr in seal.fields:
                column(attr)
                if attr in encrypted:
                    raise ValueError(f"{model.__name__}.{attr} is encrypted; encryption already authenticates it, so do not seal it")
            if seal.column in seal.fields:
                raise ValueError("the seal column cannot be one of the sealed fields")

        pk_keys = [mapper.get_property_by_column(col).key for col in mapper.primary_key]
        if assign_id is not None and len(pk_keys) != 1:
            raise ValueError("assign_id supports single-column primary keys only")

        self._configs[model] = _Config(
            mapper=mapper,
            table=mapper.local_table.name,
            pk_keys=pk_keys,
            encrypted=list(encrypted),
            blind=blind_map,
            seal=seal,
            assign_id=assign_id,
        )
        event.listen(model, "before_insert", self._before_insert, propagate=True)
        event.listen(model, "before_update", self._before_update, propagate=True)
        event.listen(model, "after_insert", self._after_flush, propagate=True)
        event.listen(model, "after_update", self._after_flush, propagate=True)
        event.listen(model, "load", self._on_load, propagate=True)
        event.listen(model, "refresh", self._on_refresh, propagate=True)
        return model

    # ------------------------------------------------------------------ public helpers

    def blind_filter(self, model: type, source_attr: str, value: str):
        """Criterion for exact-match search on an encrypted column: `select(User).where(secure.blind_filter(...))`."""
        cfg = self._config_for_class(model)
        for index_attr, (source, mode) in cfg.blind.items():
            if source == source_attr:
                candidates = self.indexer.candidates(value, make_context(cfg.table, source), mode=mode)
                return getattr(model, index_attr).in_(candidates)
        raise ValueError(f"{model.__name__}.{source_attr} has no blind index")

    def needs_rotation(self, obj: Any) -> bool:
        """True when the row holds anything written under a key other than the current primary."""
        return bool(self._stale(obj))

    def mark_for_rotation(self, obj: Any) -> None:
        """Flag what must be rewritten; the next flush re-encrypts, re-indexes and re-seals under the primary key."""
        for attr in self._stale(obj):
            attributes.flag_modified(obj, attr)

    def _stale(self, obj: Any) -> List[str]:
        """Attributes to flag so the flush rewrites everything still under an older key."""
        cfg = self._config_for(obj)
        state = attributes.instance_state(obj)
        primary = self._ring.primary_kid
        stale = [attr for attr, kid in state.info.get(_KIDS, {}).items() if kid != primary]
        for index_attr, (source, _) in cfg.blind.items():
            kid = _kid_of(state.dict.get(index_attr), 0)
            if kid is not None and kid != primary and source not in stale:
                stale.append(source)
        if cfg.seal:
            kid = _kid_of(state.dict.get(cfg.seal.column), 1)
            if kid is not None and kid != primary:
                stale.append(cfg.seal.column)
        return stale

    def verify_seal(self, obj: Any) -> bool:
        """Check a loaded row against its stored seal (loads any sealed column that is not loaded yet)."""
        cfg = self._config_for(obj)
        if cfg.seal is None:
            raise ValueError("this model has no seal configured")
        return self._verify(cfg, obj, lazy=True)

    # ------------------------------------------------------------------ flush events

    def _before_insert(self, mapper, connection, target):
        self._prepare(target, connection, inserting=True)

    def _before_update(self, mapper, connection, target):
        self._prepare(target, connection, inserting=False)

    def _prepare(self, target, connection, *, inserting: bool) -> None:
        cfg = self._config_for(target)
        state = attributes.instance_state(target)

        if inserting and cfg.assign_id is not None and state.dict.get(cfg.pk_keys[0]) is None:
            setattr(target, cfg.pk_keys[0], cfg.assign_id())
        pk = self._pk_parts(cfg, state)

        for index_attr, (source, mode) in cfg.blind.items():
            if inserting or _changed(state, source):
                value = state.dict.get(source)
                index = None if value is None else self.indexer.index(value, make_context(cfg.table, source), mode=mode)
                setattr(target, index_attr, index)

        if cfg.seal is not None:
            if inserting:
                self._reject_unset_defaults(cfg, state)
                values = {attr: state.dict.get(attr) for attr in cfg.seal.fields}
            else:
                values = self._values_for_reseal(cfg, connection, state, pk)
            setattr(target, cfg.seal.column, self.sealer.seal(self._seal_record(cfg, values), self._seal_context(cfg, pk)))

        stash = state.info.setdefault(_STASH, {})
        kids = state.info.setdefault(_KIDS, {})
        for attr in cfg.encrypted:
            if not (inserting or _changed(state, attr)):
                continue
            value = state.dict.get(attr)
            if value is None or isinstance(value, _Token):
                continue
            if not isinstance(value, str):
                raise TypeError(f"{cfg.table}.{attr} is encrypted text; convert {type(value).__name__} to str first")
            stash[attr] = value
            kids[attr] = self._ring.primary_kid
            setattr(target, attr, _Token(self.cipher.encrypt(value, make_context(cfg.table, attr, *pk))))

    def _after_flush(self, mapper, connection, target):
        state = attributes.instance_state(target)
        for attr, plaintext in state.info.pop(_STASH, {}).items():
            attributes.set_committed_value(target, attr, plaintext)

    # ------------------------------------------------------------------ load events

    def _on_load(self, target, context):
        self._after_load(target, None, initial=True)

    def _on_refresh(self, target, context, attrs):
        self._after_load(target, attrs, initial=False)

    def _after_load(self, target, attrs, *, initial: bool) -> None:
        cfg = self._config_for(target)
        state = attributes.instance_state(target)
        pk = self._pk_parts(cfg, state)
        kids = state.info.setdefault(_KIDS, {})
        for attr in cfg.encrypted:
            if attrs is not None and attr not in attrs:
                continue
            value = state.dict.get(attr)
            if isinstance(value, _Token):
                kids[attr] = _kid_of(value, 1) or ""
                plaintext = self.cipher.decrypt_str(value, make_context(cfg.table, attr, *pk))
                attributes.set_committed_value(target, attr, plaintext)

        if cfg.seal is not None and cfg.seal.verify_on_load:
            needed = [*cfg.seal.fields, cfg.seal.column]
            # Only a load that brought in every sealed column (and the seal) at once can be checked: a partial
            # refresh mixes database values with in-memory ones, and pending changes would look like tampering.
            if initial or attrs is None or set(needed) <= set(attrs):
                missing = [key for key in needed if key not in state.dict]
                if missing and initial:
                    raise SecureKitError(
                        f"{cfg.table} is sealed but was loaded without {missing}; load every sealed column "
                        "or set verify_on_load=False and call verify_seal() yourself"
                    )
                if not missing and not self._verify(cfg, target, lazy=False):
                    raise TamperedRowError(f"{cfg.table} row {pk} does not match its seal")

    # ------------------------------------------------------------------ internals

    def _config_for_class(self, model: type) -> _Config:
        for klass in model.__mro__:
            if klass in self._configs:
                return self._configs[klass]
        raise SecureKitError(f"{model.__name__} is not registered with SecureModels")

    def _config_for(self, obj: Any) -> _Config:
        return self._config_for_class(type(obj))

    @staticmethod
    def _pk_parts(cfg: _Config, state) -> List[Union[int, str]]:
        values = list(state.key[1]) if state.key is not None else [state.dict.get(key) for key in cfg.pk_keys]
        if any(value is None for value in values):
            raise SecureKitError(
                f"{cfg.table}: the primary key must be set before the flush because it is bound into every ciphertext. "
                "Use client-generated ids (for example assign_id=lambda: str(uuid.uuid4())); autoincrement keys do not work."
            )
        return [_part(value) for value in values]

    @staticmethod
    def _reject_unset_defaults(cfg: _Config, state) -> None:
        """Column defaults are applied after the seal is computed, so the stored value would not match the seal."""
        for attr in cfg.seal.fields:
            column = cfg.mapper.columns[attr]
            if attr not in state.dict and (column.default is not None or column.server_default is not None):
                raise SecureKitError(
                    f"{cfg.table}.{attr} is sealed and has a column default, which is applied after the seal is "
                    "computed. Set the value explicitly (for example in the constructor)."
                )

    @staticmethod
    def _seal_context(cfg: _Config, pk: Sequence[Union[int, str]]) -> str:
        return make_context(cfg.table, "seal", *pk)

    @staticmethod
    def _seal_record(cfg: _Config, values: Mapping[str, Any]) -> Dict[str, Any]:
        record = {}
        for attr in cfg.seal.fields:
            value = values[attr]
            transform = cfg.seal.transforms.get(attr)
            record[attr] = transform(value) if transform and value is not None else value
        return record

    def _values_for_reseal(self, cfg: _Config, connection, state, pk) -> Dict[str, Any]:
        """
        Sealed values for the new seal of an UPDATE. Values already in memory were verified when the row was
        loaded. If any are missing (the object was expired), the stored row is read and verified first, so a
        tampered column is never silently re-sealed as if it were legitimate.
        """
        fields = cfg.seal.fields
        if all(attr in state.dict for attr in fields):
            return {attr: state.dict[attr] for attr in fields}

        columns = [cfg.mapper.columns[attr] for attr in fields] + [cfg.mapper.columns[cfg.seal.column]]
        conditions = [column == value for column, value in zip(cfg.mapper.primary_key, state.key[1])]
        row = connection.execute(select(*columns).where(*conditions)).first()
        if row is None:
            raise SecureKitError(f"{cfg.table} row {pk} disappeared while it was being updated")
        stored = {attr: row[i] for i, attr in enumerate(fields)}
        seal = row[len(fields)]
        record = self._seal_record(cfg, stored)
        if not isinstance(seal, str) or not self.sealer.verify(record, self._seal_context(cfg, pk), seal):
            raise TamperedRowError(f"{cfg.table} row {pk} does not match its seal")
        return {attr: state.dict[attr] if attr in state.dict else stored[attr] for attr in fields}

    def _verify(self, cfg: _Config, target, *, lazy: bool) -> bool:
        state = attributes.instance_state(target)
        pk = self._pk_parts(cfg, state)
        stored = getattr(target, cfg.seal.column) if lazy else state.dict.get(cfg.seal.column)
        if not isinstance(stored, str):
            return False
        values = {attr: getattr(target, attr) if lazy else state.dict[attr] for attr in cfg.seal.fields}
        return self.sealer.verify(self._seal_record(cfg, values), self._seal_context(cfg, pk), stored)
