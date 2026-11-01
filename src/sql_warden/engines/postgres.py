import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg import errors

from sql_warden.engines.base import (
    Column,
    EngineUnavailable,
    QueryFailed,
    QueryTimeout,
    Result,
    Table,
)

# information_schema lists only what the connecting role has privileges on.
_TABLES_SQL = """
    SELECT c.table_schema, c.table_name, c.column_name, c.data_type
    FROM information_schema.columns c
    JOIN information_schema.tables t USING (table_schema, table_name)
    WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
      AND t.table_type IN ('BASE TABLE', 'VIEW')
    ORDER BY c.table_schema, c.table_name, c.ordinal_position
"""


class PostgresEngine:
    """Runs queries in a read-only transaction with a statement timeout and a row cap.

    These are defence in depth: they hold even if every check in front of them is wrong.
    """

    def __init__(
        self,
        dsn: str,
        *,
        statement_timeout_ms: int = 5_000,
        max_rows: int = 1_000,
        connect_timeout_s: int = 5,
    ) -> None:
        if statement_timeout_ms <= 0:
            raise ValueError("statement_timeout_ms must be positive")
        if max_rows <= 0:
            raise ValueError("max_rows must be positive")
        if connect_timeout_s <= 0:
            raise ValueError("connect_timeout_s must be positive")
        self._dsn = dsn
        self.statement_timeout_ms = statement_timeout_ms
        self.max_rows = max_rows
        self._connect_timeout_s = connect_timeout_s

    def execute(self, sql: str) -> Result:
        started = time.perf_counter()
        # A server-side cursor streams rows, so the row cap bounds memory too.
        # It also only accepts queries: Postgres rejects anything else in DECLARE.
        with self._read_only() as conn, conn.cursor(name="sql_warden") as cur:
            cur.execute(sql)
            fetched = cur.fetchmany(self.max_rows + 1)
            columns = tuple(col.name for col in cur.description or ())

        return Result(
            columns=columns,
            rows=tuple(tuple(row) for row in fetched[: self.max_rows]),
            truncated=len(fetched) > self.max_rows,
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def tables(self) -> tuple[Table, ...]:
        with self._read_only() as conn:
            rows = conn.execute(_TABLES_SQL).fetchall()
        columns: dict[tuple[str, str], list[Column]] = {}
        for schema, table, column, data_type in rows:
            columns.setdefault((schema, table), []).append(Column(column, data_type))
        return tuple(Table(schema, name, tuple(cols)) for (schema, name), cols in columns.items())

    @contextmanager
    def _read_only(self) -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
        """A connection in a read-only transaction with the statement timeout, rolled back after.

        Database errors inside the block come out as engine errors.
        """
        try:
            conn = psycopg.connect(self._dsn, connect_timeout=self._connect_timeout_s)
        except psycopg.OperationalError as exc:
            raise EngineUnavailable(f"could not connect to the database: {exc}") from exc

        with conn:
            conn.read_only = True
            try:
                conn.execute(
                    "SELECT set_config('statement_timeout', %s, true)",
                    (str(self.statement_timeout_ms),),
                )
                yield conn
            except errors.QueryCanceled as exc:
                raise QueryTimeout(
                    f"query cancelled after the {self.statement_timeout_ms} ms statement timeout"
                ) from exc
            except psycopg.Error as exc:
                raise QueryFailed(str(exc).strip(), exc.sqlstate) from exc
            finally:
                conn.rollback()
