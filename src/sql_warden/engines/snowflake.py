"""Snowflake, through its Python connector: `pip install 'sql-warden[snowflake]'`.

The connector is imported only when a connection is opened, so the rest of sql-warden runs
without it, and it is used through the few methods named here.

Snowflake has no read-only session to ask for, as Postgres has a read-only transaction. What
holds if every check is wrong is the role: connect as one that has been granted only SELECT.
The engine adds a statement timeout, one statement per request and a row cap, all enforced by
Snowflake itself.
"""

import json
import math
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing, suppress
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Protocol, Self
from urllib.parse import parse_qsl, unquote, urlsplit

from sql_warden.engines.base import (
    Column,
    CostEstimate,
    EngineError,
    EngineUnavailable,
    QueryFailed,
    QueryTimeout,
    Result,
    Table,
)

SCHEME = "snowflake"
DSN_FORM = "snowflake://USER:PASSWORD@ACCOUNT/DATABASE/SCHEMA?warehouse=WAREHOUSE&role=ROLE"
_OPTIONS = ("warehouse", "role", "authenticator", "private_key_file", "private_key_file_pwd")
BYTES = "bytes"

# INFORMATION_SCHEMA shows only what the connecting role has privileges on, in the
# connection's database.
_TABLES_SQL = """
    SELECT table_schema, table_name, column_name, data_type
    FROM information_schema.columns
    WHERE table_schema <> 'INFORMATION_SCHEMA'
    ORDER BY table_schema, table_name, ordinal_position
"""
# Compiles the statement without running it, and needs no running warehouse.
_EXPLAIN = "EXPLAIN USING JSON "
_CANCELLED = "57014"
"""The SQLSTATE of a statement Snowflake cancelled: its timeout, most often."""


class _Cursor(Protocol):
    @property
    def description(self) -> Sequence[Any] | None: ...
    def execute(self, operation: str, **options: Any) -> Any: ...
    def fetchmany(self, size: int) -> Sequence[Sequence[Any]]: ...
    def fetchone(self) -> Sequence[Any] | None: ...
    def fetchall(self) -> Sequence[Sequence[Any]]: ...
    def close(self) -> Any: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...
    def close(self) -> Any: ...


Connect = Callable[..., _Connection]
"""snowflake.connector.connect, or what stands in for it in a test."""


@dataclass(frozen=True)
class SnowflakeDsn:
    """Where and as whom to connect, from a snowflake:// URL."""

    account: str
    user: str
    database: str
    schema: str
    """As Snowflake stores it: upper case. Tables named without a schema are looked up here."""
    password: str | None = field(default=None, repr=False)
    warehouse: str | None = None
    role: str | None = None
    authenticator: str | None = None
    private_key_file: str | None = None
    private_key_file_pwd: str | None = field(default=None, repr=False)

    @classmethod
    def parse(cls, dsn: str) -> Self:
        """Raises ValueError, with a message that never repeats the DSN: it holds a password."""
        try:
            parts = urlsplit(dsn)
            port = parts.port
        except ValueError:
            raise ValueError(f"not a Snowflake connection string; write it as {DSN_FORM}") from None
        if parts.scheme != SCHEME:
            raise ValueError(
                f"a Snowflake connection string starts with {SCHEME}://; write it as {DSN_FORM}"
            )
        if not parts.hostname or not parts.username:
            raise ValueError(f"the connection string needs a user and an account: {DSN_FORM}")
        if port is not None:
            raise ValueError(
                "the connection string names an account, not a host and port: "
                f"{SCHEME}://USER@myorg-myaccount/..."
            )
        path = [unquote(part) for part in parts.path.split("/") if part]
        if not 1 <= len(path) <= 2:
            raise ValueError(
                "the connection string needs the database, and may name the schema, after "
                f"the account: {DSN_FORM}"
            )
        options = dict(parse_qsl(parts.query, keep_blank_values=True))
        unknown = sorted(set(options) - set(_OPTIONS))
        if unknown:
            raise ValueError(
                f"unknown connection option{'s' if len(unknown) > 1 else ''} "
                f"{', '.join(unknown)}; sql-warden takes {', '.join(_OPTIONS)}"
            )
        return cls(
            account=parts.hostname,
            user=unquote(parts.username),
            password=None if parts.password is None else unquote(parts.password),
            database=path[0].upper(),
            schema=(path[1] if len(path) == 2 else "PUBLIC").upper(),
            **options,
        )

    def describe(self) -> str:
        """Who connects where, for display: never the password."""
        extras = [
            f"{name} {value}"
            for name, value in (("role", self.role), ("warehouse", self.warehouse))
            if value
        ]
        described = f"{self.account}/{self.database}/{self.schema} as {self.user}"
        return described + (f" ({', '.join(extras)})" if extras else "")

    def connect_args(self) -> dict[str, Any]:
        named = {
            "account": self.account,
            "user": self.user,
            "password": self.password,
            "database": self.database,
            "schema": self.schema,
            "warehouse": self.warehouse,
            "role": self.role,
            "authenticator": self.authenticator,
            "private_key_file": self.private_key_file,
            "private_key_file_pwd": self.private_key_file_pwd,
        }
        return {name: value for name, value in named.items() if value is not None}


def format_bytes(count: float) -> str:
    """A number of bytes as people read it: 512 B, 1.2 MiB, 10 GiB."""
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            break
        size /= 1024
    return f"{size:,.0f} {unit}" if size == int(size) or unit == "B" else f"{size:,.1f} {unit}"


def _operations(plan: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    # A list of steps, each a list of operations; most queries have one step.
    return [operation for step in plan.get("Operations", ()) for operation in step]


def describe_operation(operation: Mapping[str, Any]) -> str:
    """A plan operation in a few words: "TableScan on DB.PUBLIC.ORDERS (12 of 400
    partitions)"."""
    name = str(operation.get("operation", "?"))
    objects = operation.get("objects") or ()
    if objects:
        name += f" on {', '.join(str(o) for o in objects)}"
    assigned, total = operation.get("partitionsAssigned"), operation.get("partitionsTotal")
    if assigned is not None and total is not None:
        name += f" ({assigned:,} of {total:,} partitions)"
    return name


def cost_estimate(plan: Mapping[str, Any]) -> CostEstimate:
    """EXPLAIN USING JSON's output as a CostEstimate.

    The cost is the bytes in the micro-partitions left after pruning: what the query may
    scan, an upper bound. Snowflake's plan has no row estimate, and no measure of the work
    done on those bytes: a join of two small tables that multiplies them scans little. The
    statement timeout is what bounds that."""
    try:
        total = float(plan["GlobalStats"]["bytesAssigned"])
        operations = _operations(plan)
        if not operations:
            raise KeyError("Operations")
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise EngineError("EXPLAIN returned a plan sql-warden can't read") from exc
    # The first of equals, and the root (the Result) when nothing is scanned at all.
    costliest = max(operations, key=lambda op: float(op.get("bytesAssigned") or 0))
    return CostEstimate(
        total_cost=total,
        est_rows=None,
        top_node=describe_operation(costliest),
        unit=BYTES,
        raw=plan,
    )


def _connector() -> ModuleType:
    try:
        import snowflake.connector
    except ImportError as exc:
        raise EngineUnavailable(
            "the Snowflake engine needs Snowflake's connector, which isn't installed: "
            "pip install 'sql-warden[snowflake]'"
        ) from exc
    module: ModuleType = snowflake.connector
    return module


def _message(exc: BaseException) -> str:
    """Snowflake's own words for an error, without the ids the connector adds."""
    raw = getattr(exc, "raw_msg", None)
    return (raw if isinstance(raw, str) and raw else str(exc)).strip()


class SnowflakeEngine:
    """Runs queries over one Snowflake session, opened on first use and reopened if it is
    lost. Threads share it: the connector lets them.

    The session's statement timeout covers every statement, the catalog and EXPLAIN included,
    and its MULTI_STATEMENT_COUNT of 1 makes Snowflake refuse a second statement. Each query
    is also capped at the row cap plus one by Snowflake (ROWS_PER_RESULTSET), whatever its
    LIMIT says.
    """

    def __init__(
        self,
        dsn: str,
        *,
        statement_timeout_ms: int = 5_000,
        max_rows: int = 1_000,
        connect_timeout_s: int = 5,
        connect: Connect | None = None,
    ) -> None:
        if statement_timeout_ms <= 0:
            raise ValueError("statement_timeout_ms must be positive")
        if max_rows <= 0:
            raise ValueError("max_rows must be positive")
        if connect_timeout_s <= 0:
            raise ValueError("connect_timeout_s must be positive")
        self._target = SnowflakeDsn.parse(dsn)
        self.statement_timeout_ms = statement_timeout_ms
        # Snowflake counts in whole seconds; round up, so a query gets at least what was asked.
        self.statement_timeout_s = max(1, math.ceil(statement_timeout_ms / 1000))
        self.max_rows = max_rows
        self._connect_timeout_s = connect_timeout_s
        self._connect = connect
        self._conn: _Connection | None = None
        self._lock = threading.Lock()

    @property
    def default_schema(self) -> str:
        """The session's schema, where a table named without one is looked up."""
        return self._target.schema

    def execute(self, sql: str, *, tag: str | None = None) -> Result:
        started = time.perf_counter()
        options = self._statement(tag, ROWS_PER_RESULTSET=self.max_rows + 1)

        def run(conn: _Connection) -> tuple[tuple[str, ...], Sequence[Sequence[Any]]]:
            with closing(conn.cursor()) as cur:
                cur.execute(sql, _statement_params=options)
                fetched = cur.fetchmany(self.max_rows + 1)
                return tuple(str(column.name) for column in cur.description or ()), fetched

        columns, fetched = self._attempt(run)
        return Result(
            columns=columns,
            rows=tuple(tuple(row) for row in fetched[: self.max_rows]),
            truncated=len(fetched) > self.max_rows,
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def explain(self, sql: str, *, tag: str | None = None) -> CostEstimate:
        options = self._statement(tag)

        def run(conn: _Connection) -> Sequence[Any] | None:
            with closing(conn.cursor()) as cur:
                cur.execute(_EXPLAIN + sql, _statement_params=options)
                return cur.fetchone()

        row = self._attempt(run)
        if not row:
            raise EngineError("EXPLAIN returned no plan")
        plan = row[0]
        if isinstance(plan, str | bytes):
            try:
                plan = json.loads(plan)
            except ValueError as exc:
                raise EngineError("EXPLAIN returned a plan sql-warden can't read") from exc
        if not isinstance(plan, Mapping):
            raise EngineError("EXPLAIN returned a plan sql-warden can't read")
        return cost_estimate(plan)

    def tables(self) -> tuple[Table, ...]:
        def run(conn: _Connection) -> Sequence[Sequence[Any]]:
            with closing(conn.cursor()) as cur:
                cur.execute(_TABLES_SQL)
                return cur.fetchall()

        columns: dict[tuple[str, str], list[Column]] = {}
        for schema, table, column, data_type in self._attempt(run):
            columns.setdefault((schema, table), []).append(Column(column, data_type))
        return tuple(Table(schema, name, tuple(cols)) for (schema, name), cols in columns.items())

    def close(self) -> None:
        with self._lock:
            self._drop()

    def _statement(self, tag: str | None, **parameters: Any) -> dict[str, Any]:
        """Parameters for one statement only: the session keeps none of them."""
        if tag is not None:
            parameters["QUERY_TAG"] = tag
        return parameters

    def _attempt[T](self, action: Callable[[_Connection], T]) -> T:
        # Two tries: a session that was lost since last time (they expire when idle) gets
        # one fresh replacement. Everything here only reads, so trying again is safe.
        try:
            return action(self._connection())
        except Exception as exc:
            error = self._translated(exc)
            if error is None:
                raise
            if not isinstance(error, EngineUnavailable):
                raise error from exc
            with self._lock:
                self._drop()
        try:
            return action(self._connection())
        except Exception as exc:
            error = self._translated(exc)
            if error is None:
                raise
            raise error from exc

    def _connection(self) -> _Connection:
        with self._lock:
            if self._conn is None:
                self._conn = self._open()
            return self._conn

    def _open(self) -> _Connection:
        connect = self._connect or _connector().connect
        try:
            return connect(
                **self._target.connect_args(),
                application="sql-warden",
                login_timeout=self._connect_timeout_s,
                session_parameters={
                    "STATEMENT_TIMEOUT_IN_SECONDS": self.statement_timeout_s,
                    "MULTI_STATEMENT_COUNT": 1,
                    "QUERY_TAG": "sql-warden",
                },
            )
        except EngineError:
            raise
        except Exception as exc:
            # The connector's own errors say why; anything else is named, not quoted, since
            # it was raised with the connection's settings in hand.
            reason = _message(exc) if self._is_connector_error(exc) else type(exc).__name__
            raise EngineUnavailable(f"could not connect to Snowflake: {reason}") from exc

    def _drop(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            with suppress(Exception):  # it is being thrown away for being broken
                conn.close()

    def _is_connector_error(self, exc: BaseException) -> bool:
        try:
            errors = _connector().errors
        except EngineUnavailable:
            return False
        return isinstance(exc, errors.Error)

    def _translated(self, exc: Exception) -> EngineError | None:
        """exc as an engine error, or None if it isn't Snowflake's: a bug, to be raised as
        it is."""
        if isinstance(exc, EngineError):
            return exc
        if not self._is_connector_error(exc):
            return None
        errors = _connector().errors
        sqlstate = getattr(exc, "sqlstate", None)
        message = _message(exc)
        if sqlstate == _CANCELLED:
            return QueryTimeout(
                f"query cancelled (the statement timeout is {self.statement_timeout_s} s): "
                f"{message}"
            )
        lost = isinstance(exc, errors.OperationalError | errors.InterfaceError)
        if lost or (isinstance(sqlstate, str) and sqlstate.startswith("08")):
            return EngineUnavailable(f"could not reach Snowflake: {message}")
        return QueryFailed(message, sqlstate if isinstance(sqlstate, str) else None)
