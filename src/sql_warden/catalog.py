"""The warehouse's tables and columns, read from the engine and reused across queries."""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from sqlglot import exp
from sqlglot.errors import ParseError
from sqlglot.schema import MappingSchema

from sql_warden.engines import Engine, Table

DEFAULT_MAX_AGE_S = 60.0
"""How long a read of the catalog is reused; a new table shows up within this long."""
UNKNOWN_TYPE = "UNKNOWN"


def column_type(data_type: str, dialect: str) -> str:
    """A catalog type as sqlglot reads it, or UNKNOWN for types sqlglot can't parse."""
    try:
        return exp.DataType.build(data_type, dialect=dialect).sql(dialect=dialect)
    except ParseError:
        return UNKNOWN_TYPE


@dataclass(frozen=True)
class _Snapshot:
    tables: tuple[Table, ...]
    by_name: dict[tuple[str, str], Table]
    schema: MappingSchema
    read_at: float


class Catalog:
    """What the engine's role can read, as tables and as a sqlglot schema for the checks.

    Names are kept exactly as the database stores them, and the schema does not normalize them
    again: sqlglot folds an unquoted name in a query to the dialect's case before looking it up,
    so `PRODUCTS` finds products and `"MixedCase"` finds only MixedCase, as in Postgres.
    """

    def __init__(
        self,
        engine: Engine,
        *,
        dialect: str = "postgres",
        max_age_s: float = DEFAULT_MAX_AGE_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_age_s < 0:
            raise ValueError("max_age_s must not be negative")
        self._engine = engine
        self._dialect = dialect
        self._max_age_s = max_age_s
        self._clock = clock
        self._lock = threading.Lock()
        self._snapshot: _Snapshot | None = None

    def tables(self) -> tuple[Table, ...]:
        return self._current().tables

    def table(self, schema: str, name: str) -> Table | None:
        """The table with exactly this schema and name, if the role can read it."""
        return self._current().by_name.get((schema, name))

    def schema(self) -> MappingSchema:
        return self._current().schema

    def refresh(self) -> None:
        """Forget the last read, so the next use reads the catalog again."""
        with self._lock:
            self._snapshot = None

    def _current(self) -> _Snapshot:
        # One read at a time: concurrent callers wait for it instead of each querying.
        with self._lock:
            snapshot = self._snapshot
            if snapshot is None or self._clock() - snapshot.read_at >= self._max_age_s:
                # An engine error propagates and is not cached; the next call tries again.
                snapshot = self._snapshot = self._read()
            return snapshot

    def _read(self) -> _Snapshot:
        read_at = self._clock()
        tables = self._engine.tables()
        mapping: dict[str, dict[str, dict[str, str]]] = {}
        for table in tables:
            mapping.setdefault(table.schema, {})[table.name] = {
                column.name: column_type(column.type, self._dialect) for column in table.columns
            }
        return _Snapshot(
            tables=tables,
            by_name={(table.schema, table.name): table for table in tables},
            schema=MappingSchema(dict(mapping), dialect=self._dialect, normalize=False),
            read_at=read_at,
        )
