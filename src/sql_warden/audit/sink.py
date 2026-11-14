"""Where audit events go: a Postgres table in production, a list in tests."""

import datetime
import json
import threading
import uuid
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass, field
from importlib.resources import files
from typing import Any, Literal, Protocol

import psycopg
from psycopg.types.json import Jsonb

from sql_warden.sessions import Usage

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
    profile: str | None
    """None for a request refused before it had one: one that failed authentication."""
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
    identity: str | None = None
    """Who the caller is, when it authenticated: an API key's name, or oidc:<subject>."""
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    ts: datetime.datetime = field(default_factory=lambda: datetime.datetime.now(datetime.UTC))


def usage_from(events: Iterable[AuditEvent], *, not_counted: Collection[str] = ()) -> Usage:
    """What the requests in events used: the rule for reading a session's usage back out of
    the audit log.

    A query counts, with its estimated cost, if it was sent to the database: allowed or
    failed, and not a dry run. Rows count where they came back. A refusal counts, dry runs
    included, unless its code is in not_counted."""
    queries, total_cost, rows_returned, refusals = 0, 0.0, 0, 0
    for event in events:
        if event.decision == "refused":
            refusals += event.code not in not_counted
        elif not event.dry_run:
            queries += 1
            total_cost += event.cost_estimate or 0.0
            rows_returned += event.rows_returned or 0
    return Usage(queries, total_cost, rows_returned, refusals)


class AuditSink(Protocol):
    def usage(self, session_id: str, profile: str, *, not_counted: Collection[str] = ()) -> Usage:
        """What the session has used under the profile, by the records so far (see
        usage_from), or raise AuditError. How a budget outlives the server that counted it."""
        ...

    def ping(self) -> None:
        """Raise AuditError if events can't be recorded right now. Checked before a query
        runs, so the warehouse isn't queried while the audit database is down."""
        ...

    def record(self, event: AuditEvent) -> None:
        """Store the event, or raise AuditError. A caller must not return anything it could
        not record."""
        ...


class MemoryAuditSink:
    """Keeps events in a list: for tests, and for running without an audit database."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()
        self.fail_with: AuditError | None = None
        """Set to make every record() fail, as an unreachable database would."""

    def ping(self) -> None:
        if self.fail_with is not None:
            raise self.fail_with

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            if self.fail_with is not None:
                raise self.fail_with
            self._events.append(event)

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def usage(self, session_id: str, profile: str, *, not_counted: Collection[str] = ()) -> Usage:
        self.ping()
        mine = (e for e in self.events if (e.session_id, e.profile) == (session_id, profile))
        return usage_from(mine, not_counted=not_counted)


# usage_from, in SQL.
_USAGE = """
    SELECT
        count(*) FILTER (WHERE decision <> 'refused' AND NOT dry_run),
        coalesce(sum(cost_estimate) FILTER (WHERE decision <> 'refused' AND NOT dry_run), 0),
        coalesce(sum(rows_returned) FILTER (WHERE decision <> 'refused' AND NOT dry_run), 0),
        count(*) FILTER (
            WHERE decision = 'refused'
              AND (code IS NULL OR code <> ALL (%(not_counted)s::text[]))
        )
    FROM audit_events
    WHERE session_id = %(session_id)s AND profile = %(profile)s
"""

_INSERT = """
    INSERT INTO audit_events (
        id, ts, session_id, client, profile, dry_run, sql, executed_sql, rewrites, decision,
        refused_by, code, reason, error, cost_estimate, rows_returned, truncated,
        masked_columns, duration_ms, trace, identity
    ) VALUES (
        %(id)s, %(ts)s, %(session_id)s, %(client)s, %(profile)s, %(dry_run)s, %(sql)s,
        %(executed_sql)s, %(rewrites)s, %(decision)s, %(refused_by)s, %(code)s, %(reason)s,
        %(error)s, %(cost_estimate)s, %(rows_returned)s, %(truncated)s, %(masked_columns)s,
        %(duration_ms)s, %(trace)s, %(identity)s
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

    def ping(self) -> None:
        with self._lock:
            self._attempt(
                lambda conn: conn.execute("SELECT 1"), "the audit database is unavailable"
            )

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

    def usage(self, session_id: str, profile: str, *, not_counted: Collection[str] = ()) -> Usage:
        params = {
            "session_id": session_id,
            "profile": profile,
            "not_counted": [str(code) for code in not_counted],
        }
        with self._lock:
            row = self._attempt(
                lambda conn: conn.execute(_USAGE, params).fetchone(),
                "could not read the session's usage from the audit log",
            )
        assert row is not None  # an aggregate without GROUP BY always returns one row
        queries, total_cost, rows_returned, refusals = row
        return Usage(int(queries), float(total_cost), int(rows_returned), int(refusals))

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _apply_schema(self, conn: psycopg.Connection[Any]) -> None:
        with conn.transaction():
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (_SCHEMA_LOCK,))
            conn.execute(SCHEMA.read_text())

    def _attempt[T](self, action: Callable[[psycopg.Connection[Any]], T], what: str) -> T:
        # Two tries: a connection that broke since last time gets one fresh replacement.
        try:
            return action(self._connection())
        except psycopg.OperationalError:
            self._drop()
        except psycopg.Error as exc:
            raise AuditError(f"{what}: {str(exc).strip()}") from exc
        try:
            return action(self._connection())
        except psycopg.Error as exc:
            self._drop()
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
    "identity",
)
