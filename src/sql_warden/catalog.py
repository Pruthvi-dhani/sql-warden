"""The catalog: what the target database contains, and the TTL cache in front of it.

Two jobs, both load-bearing for RESOLVE (plan.md §4.2 stage 3).

The first is `to_sqlglot_schema()`. sqlglot's `qualify()` does the actual resolution work --
unknown tables and columns raise `OptimizeError`, which *is* the RESOLVE rejection
(implementation-plan.md finding #3) -- but only if it is handed a schema describing reality.
This module is that bridge.

The second is identifier folding. Every name here is normalised through the engine's own
dialect rules, so `Catalog.table()` and the `MappingSchema` given to `qualify()` agree on
what counts as the same table. If they disagreed, a column could resolve under one spelling
and be matched by policy under another -- which is the masking-laundering failure the
project exists to prevent, arriving through the back door.

Dataclasses rather than `FrozenModel`: nothing here is parsed from user input. A catalog is
built by introspecting a live database, so Pydantic's validation has nothing to validate,
and `Deny` next door already sets the precedent for internal value types.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from types import MappingProxyType

from sqlglot import exp
from sqlglot.dialects.dialect import Dialect
from sqlglot.schema import MappingSchema


def fold(name: str, dialect: str) -> str:
    """Fold an identifier the way `dialect` itself would.

    Postgres lowercases an unquoted identifier, Snowflake uppercases it. Getting this from
    sqlglot rather than hand-rolling `.lower()` means the rule stays the engine's rule, and
    a third engine with different folding does not silently inherit Postgres semantics.
    """
    return Dialect.get_or_raise(dialect).normalize_identifier(exp.to_identifier(name)).name


@dataclass(frozen=True, slots=True)
class Column:
    name: str
    data_type: str
    nullable: bool
    is_primary_key: bool = False
    #: Fully qualified `schema.table.column` this column references, when it is a foreign
    #: key. `describe_table` surfaces it so an agent can join without guessing.
    references: str | None = None


@dataclass(frozen=True, slots=True)
class Table:
    schema: str
    name: str
    columns: tuple[Column, ...]
    #: Planner estimate (`pg_class.reltuples` on Postgres), not `COUNT(*)`. An approximate
    #: figure that costs nothing beats an exact one that scans the table to answer "how big
    #: is this?" -- and the cost gate, not this number, is what actually stops a big query.
    row_estimate: int | None = None

    @property
    def fqn(self) -> str:
        return f"{self.schema}.{self.name}"

    def column(self, name: str, dialect: str) -> Column | None:
        folded = fold(name, dialect)
        return next((c for c in self.columns if fold(c.name, dialect) == folded), None)


class DuplicateTable(ValueError):
    """Two tables introspected under the same folded name.

    An introspection bug rather than a user error, and worth refusing to build a catalog
    over: whichever one lost the collision would be invisible to RESOLVE while remaining
    perfectly queryable on the database.
    """


@dataclass(frozen=True, slots=True)
class Catalog:
    """Everything sql-warden knows about the target, as of the last introspection.

    `dialect` is a field rather than an argument to `to_sqlglot_schema()` because identifier
    folding is a property of the database this catalog came from, not of the caller asking
    about it.
    """

    dialect: str
    tables: tuple[Table, ...]
    _by_fqn: Mapping[str, Table] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        index: dict[str, Table] = {}
        for table in self.tables:
            key = self._key(table.schema, table.name)
            if key in index:
                raise DuplicateTable(
                    f"two tables fold to {key!r} under the {self.dialect} dialect; "
                    f"one of them would be unreachable through RESOLVE"
                )
            index[key] = table
        object.__setattr__(self, "_by_fqn", MappingProxyType(index))

    def _key(self, schema: str, name: str) -> str:
        return f"{fold(schema, self.dialect)}.{fold(name, self.dialect)}"

    def table(self, schema: str, name: str) -> Table | None:
        """Look a table up by name, folding the way the engine would."""
        return self._by_fqn.get(self._key(schema, name))

    @property
    def schemas(self) -> tuple[str, ...]:
        """Every schema present, folded and deduplicated, in a stable order."""
        return tuple(sorted({fold(t.schema, self.dialect) for t in self.tables}))

    def to_sqlglot_schema(self) -> MappingSchema:
        """Render as the schema `qualify()` resolves against.

        `normalize=True` is not a formatting preference. It makes sqlglot fold identifiers
        with the same rules the database does, so a query naming `CUSTOMERS` on Postgres
        resolves against `customers` exactly as the server would resolve it.

        The trade-off, stated because it is real: a column created as a *quoted* mixed-case
        identifier folds to lower case here and can then no longer be resolved. That is a
        false rejection (`UNKNOWN_OBJECT`), never a leak, and the alternative -- dropping
        normalisation so both spellings resolve -- would let a reference reach a column
        under a spelling policy matching did not recognise. Fail closed.
        """
        nested: dict[str, dict[str, dict[str, str]]] = {}
        for table in self.tables:
            columns = {column.name: column.data_type for column in table.columns}
            nested.setdefault(table.schema, {})[table.name] = columns
        # MappingSchema types its argument as `dict[str, object]`, and dict is invariant,
        # so the nested mapping is widened through the constructor rather than cast.
        mapping: dict[str, object] = dict(nested)
        return MappingSchema(schema=mapping, dialect=self.dialect, normalize=True)


#: Monotonic seconds. Injected so TTL expiry is tested by moving a number, not by sleeping.
Clock = Callable[[], float]

#: How a cache miss is filled. Async because introspection is I/O.
Introspect = Callable[[], Awaitable[Catalog]]


class CatalogCache:
    """A single-entry TTL cache over introspection.

    Introspection is several catalog queries against the target, and the catalog changes on
    DDL timescales, not query timescales -- so re-running it per query would be pure waste.
    `cache_ttl` in config (plan.md §5) is how long a stale catalog is tolerated.

    Two properties beyond "store it and check the clock":

    Refresh is serialised behind a lock, so N concurrent queries arriving on a cold or
    expired cache produce one introspection rather than N. An agent's first burst is
    precisely when this happens.

    A failed refresh propagates rather than extending the previous entry. Stale-on-error
    sounds friendly and is wrong here: if introspection fails because a table was dropped or
    a grant was revoked, continuing to resolve against the catalog from before is resolving
    against a database that no longer exists.
    """

    def __init__(self, ttl: timedelta, *, clock: Clock = time.monotonic) -> None:
        self._ttl = ttl.total_seconds()
        self._clock = clock
        self._lock = asyncio.Lock()
        self._catalog: Catalog | None = None
        self._loaded_at = 0.0

    def _fresh(self) -> bool:
        return self._catalog is not None and (self._clock() - self._loaded_at) < self._ttl

    async def get(self, introspect: Introspect) -> Catalog:
        """Return the cached catalog, introspecting first if it is missing or expired."""
        if self._catalog is not None and self._fresh():
            return self._catalog

        async with self._lock:
            # Re-checked under the lock: whoever held it may have just refreshed, and this
            # caller would otherwise immediately introspect again for nothing.
            if self._catalog is not None and self._fresh():
                return self._catalog
            catalog = await introspect()
            self._catalog = catalog
            self._loaded_at = self._clock()
            return catalog

    def invalidate(self) -> None:
        """Drop the entry, so the next `get()` introspects."""
        self._catalog = None
        self._loaded_at = 0.0


def catalog_of(dialect: str, tables: Iterable[Table]) -> Catalog:
    """Convenience constructor, mostly for engines assembling a catalog row by row."""
    return Catalog(dialect=dialect, tables=tuple(tables))
