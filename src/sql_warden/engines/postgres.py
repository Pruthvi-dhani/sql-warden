import time

import psycopg
from psycopg import errors

from sql_warden.engines.base import (
    EngineUnavailable,
    QueryFailed,
    QueryTimeout,
    Result,
)


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
                # A server-side cursor streams rows, so the row cap bounds memory too.
                # It also only accepts queries: Postgres rejects anything else in DECLARE.
                with conn.cursor(name="sql_warden") as cur:
                    cur.execute(sql)
                    fetched = cur.fetchmany(self.max_rows + 1)
                    columns = tuple(col.name for col in cur.description or ())
            except errors.QueryCanceled as exc:
                raise QueryTimeout(
                    f"query cancelled after the {self.statement_timeout_ms} ms statement timeout"
                ) from exc
            except psycopg.Error as exc:
                raise QueryFailed(str(exc).strip(), exc.sqlstate) from exc
            finally:
                conn.rollback()

        return Result(
            columns=columns,
            rows=tuple(tuple(row) for row in fetched[: self.max_rows]),
            truncated=len(fetched) > self.max_rows,
            duration_ms=(time.perf_counter() - started) * 1000,
        )
