"""Where audit events go: a Postgres table in production, a list in tests."""

import datetime
import json
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any, Literal, Protocol

import psycopg
from psycopg.types.json import Jsonb

Decision = Literal["allowed", "refused", "failed"]
"""allowed: the checks passed (and, unless a dry run, it ran). refused: a check stopped it.
failed: allowed, but the database failed to run it."""

SCHEMA = files("sql_warden.audit").joinpath("schema.sql")
# Serializes schema setup across servers starting at once; CREATE ... IF NOT EXISTS alone can
# still collide when two sessions create the same table.
_SCHEMA_LOCK = "sql_warden.audit.schema"


class AuditError(Exception):
    """An event could not be recorded. The message is safe to show: never a password."""


@dataclass(frozen=True)
class AuditEvent:
    profile: str
    sql: str
    """As sent, before any check rewrote it."""
    decision: Decision
    duration_ms: float
    dry_run: bool = False
    trace: tuple[dict[str, Any], ...] = ()
    """Every check that ran: check, passed, code, reason, duration_ms."""
    executed_sql: str | None = None
    rewrites: tuple[str, ...] = ()
    refused_by: str | None = None
    code: str | None = None
    reason: str | None = None
    error: str | None = None
    session_id: str | None = None
    client: str | None = None
    cost_estimate: float | None = None
    rows_returned: int | None = None
    truncated: bool | None = None
    masked_columns: tuple[str, ...] = ()
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    ts: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(datetime.UTC))


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None:
        """Store the event, or raise AuditError. A caller must not run a query it could not
        record."""
        ...


class MemoryAuditSink:
    """Keeps events in a list: for tests, and for running without an audit database."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()
        self.fail_with: AuditError | None = None
        """Set to make every record() fail, as an unreachable database would."""

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            if self.fail_with is not None:
                raise self.fail_with
            self._events.append(event)

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)


_INSERT = """
    INSERT INTO audit_events (
        id, ts, session_id, client, profile, dry_run, sql, executed_sql, rewrites, decision,
        refused_by, code, reason, error, cost_estimate, rows_returned, truncated,
        masked_columns, duration_ms, trace
    ) VALUES (
        %(id)s, %(ts)s, %(session_id)s, %(client)s, %(profile)s, %(dry_run)s, %(sql)s,
        %(executed_sql)s, %(rewrites)s, %(decision)s, %(refused_by)s, %(code)s, %(reason)s,
        %(error)s, %(cost_estimate)s, %(rows_returned)s, %(truncated)s, %(masked_columns)s,
        %(duration_ms)s, %(trace)s
    )
"""


class PostgresAuditSink:
    """Writes each event as one row of audit_events, committed before record() returns.

    One connection, reused and shared by threads; if it breaks (the database restarted, say),
    the next record() opens a new one and tries once more before giving up.
    """

    def __init__(self, dsn: str, *, connect_timeout_s: int = 5) -> None:
        self._dsn = dsn
        self._connect_timeout_s = connect_timeout_s
        self._conn: psycopg.Connection[Any] | None = None
        self._lock = threading.Lock()

    def ensure_schema(self) -> None:
        """Create audit_events if it doesn't exist. Safe to call from every server start."""
        with self._lock:
            self._attempt(self._apply_schema, "could not set up the audit table")

    def record(self, event: AuditEvent) -> None:
        params = {
            **{name: getattr(event, name) for name in _COLUMNS},
            "rewrites": list(event.rewrites),
            "masked_columns": list(event.masked_columns),
            "trace": Jsonb(list(event.trace), dumps=json.dumps),
        }
        with self._lock:
            self._attempt(
                lambda conn: conn.execute(_INSERT, params), "could not record the audit event"
            )

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _apply_schema(self, conn: psycopg.Connection[Any]) -> None:
        with conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (_SCHEMA_LOCK,))
            conn.execute(SCHEMA.read_text())

    def _attempt(self, action: Callable[[psycopg.Connection[Any]], object], what: str) -> None:
        # Two tries: a connection that broke since last time gets one fresh replacement.
        for attempt in (1, 2):
            try:
                action(self._connection())
                return
            except psycopg.OperationalError as exc:
                self._drop()
                if attempt == 2:
                    raise AuditError(f"{what}: {str(exc).strip()}") from exc
            except psycopg.Error as exc:
                raise AuditError(f"{what}: {str(exc).strip()}") from exc

    def _connection(self) -> psycopg.Connection[Any]:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg.connect(
                self._dsn, autocommit=True, connect_timeout=self._connect_timeout_s
            )
        return self._conn

    def _drop(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None


_COLUMNS = (
    "id",
    "ts",
    "session_id",
    "client",
    "profile",
    "dry_run",
    "sql",
    "executed_sql",
    "decision",
    "refused_by",
    "code",
    "reason",
    "error",
    "cost_estimate",
    "rows_returned",
    "truncated",
    "duration_ms",
)
