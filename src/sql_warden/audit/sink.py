"""Where audit events go: a Postgres table in production, a list in tests."""

import datetime
import json
import threading
import uuid
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass, field
from importlib.resources import files
from typing import TYPE_CHECKING, Any, Literal, Protocol

import psycopg
from psycopg import sql as psql
from psycopg.types.json import Jsonb

from sql_warden.audit.connections import Connections, OneConnection
from sql_warden.sessions import Usage

if TYPE_CHECKING:
    from sql_warden.audit.store import PostgresSessionStore

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
    the next action opens a new one and tries once more before giving up.
    """

    def __init__(self, dsn: str, *, connect_timeout_s: int = 5) -> None:
        self._dsn = dsn
        self._connect_timeout_s = connect_timeout_s
        self._records: Connections = OneConnection(dsn, connect_timeout_s=connect_timeout_s)

    def ensure_schema(self) -> None:
        """Make sure the audit tables are there and current. Safe to call from every start.

        A role that owns them (or finds none yet) applies the schema itself, as the demo
        stack's does. One that doesn't, the deployed writer that may only add records,
        can't run DDL and must not: it checks the tables are current and that it can add
        records, and otherwise says to run `sql-warden audit init` as their owner."""
        self._attempt(self._ensure, "could not set up the audit tables")

    def apply_schema(self, owner: str | None = None) -> None:
        """Create or update the audit tables, and grant the deploy roles what they may do:
        `sql-warden audit init`. As owner (a role this one is a member of, which then owns
        the tables) if given."""
        self._attempt(
            lambda conn: self._apply_schema(conn, owner=owner),
            "could not set up the audit tables",
        )

    def tampering(self) -> tuple[str, ...] | None:
        """Every way this role can change or remove what is already recorded, in words
        ("can UPDATE, DELETE on audit_events"); none for a role that can only add records,
        and None while there is no audit table. Asked for every role it is a member of,
        since SET ROLE would give it theirs."""
        row = self._attempt(
            lambda conn: conn.execute(_TAMPERING).fetchone(),
            "could not check what the audit role can do",
        )
        if row is None:
            return None  # no table yet: nothing recorded to change
        superuser, owner, privileges = row
        if superuser == "itself":
            return ("is a superuser",)  # a member of every role: the rest says nothing more
        found = []
        if superuser:
            found.append(f"can act as superuser {superuser}")
        if owner:
            found.append(
                "owns audit_events"
                if owner == "itself"
                else f"can act as {owner}, which owns audit_events"
            )
        if privileges:
            found.append(f"can {', '.join(privileges)} on audit_events")
        return tuple(found)

    def ping(self) -> None:
        self._attempt(lambda conn: conn.execute("SELECT 1"), "the audit database is unavailable")

    def record(self, event: AuditEvent) -> None:
        params = {
            **{name: getattr(event, name) for name in _COLUMNS},
            "rewrites": list(event.rewrites),
            "masked_columns": list(event.masked_columns),
            "trace": Jsonb(list(event.trace), dumps=json.dumps),
        }
        self._attempt(
            lambda conn: conn.execute(_INSERT, params), "could not record the audit event"
        )

    def usage(self, session_id: str, profile: str, *, not_counted: Collection[str] = ()) -> Usage:
        params = {
            "session_id": session_id,
            "profile": profile,
            "not_counted": [str(code) for code in not_counted],
        }
        row = self._attempt(
            lambda conn: conn.execute(_USAGE, params).fetchone(),
            "could not read the session's usage from the audit log",
        )
        assert row is not None  # an aggregate without GROUP BY always returns one row
        queries, total_cost, rows_returned, refusals = row
        return Usage(int(queries), float(total_cost), int(rows_returned), int(refusals))

    def session_store(
        self, profile: str, *, not_counted: Collection[str] = ()
    ) -> "PostgresSessionStore":
        """A store for the profile's budgets in this audit database, where every server
        recording here shares them. On its own connection: a charge waiting for another
        server's must not hold up the audit records."""
        from sql_warden.audit.store import PostgresSessionStore

        return PostgresSessionStore(
            self._dsn,
            profile=profile,
            not_counted=not_counted,
            connect_timeout_s=self._connect_timeout_s,
        )

    def close(self) -> None:
        self._records.close()

    def _ensure(self, conn: psycopg.Connection[Any]) -> None:
        owned = conn.execute(_OWNED).fetchone()
        if owned is None or owned[0]:
            self._apply_schema(conn)
            return
        problems = _schema_problems(conn)
        if problems:
            raise AuditError(
                f"the audit tables need updating, which role {_current_role(conn)} can't "
                f"do since it doesn't own them ({'; '.join(problems)}): run `sql-warden "
                "audit init` as their owner"
            )
        can = conn.execute("SELECT has_table_privilege('audit_events', 'INSERT')").fetchone()
        if not (can and can[0]):
            raise AuditError(
                f"role {_current_role(conn)} can't add records to audit_events: grant it "
                "sql_warden_writer (deploy/audit_roles.sql)"
            )

    def _apply_schema(self, conn: psycopg.Connection[Any], *, owner: str | None = None) -> None:
        with conn.transaction():
            if owner is not None:
                conn.execute(psql.SQL("SET LOCAL ROLE {}").format(psql.Identifier(owner)))
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (_SCHEMA_LOCK,))
            conn.execute(SCHEMA.read_text())

    def _attempt[T](self, action: Callable[[psycopg.Connection[Any]], T], what: str) -> T:
        return self._records.attempt(action, what, AuditError)


# Whether this role owns audit_events (has its owner's privileges), if it exists.
_OWNED = """
    SELECT pg_has_role(c.relowner, 'USAGE') FROM pg_class c
    WHERE c.oid = to_regclass('audit_events')
"""
# How this role could change or remove a record: as a superuser, as the owner (who may do
# anything to the table), or with a privilege that changes rows. For every role it can
# become, inherited or not.
_TAMPERING = """
    WITH roles AS (
        SELECT r.oid, r.rolname, r.rolsuper, r.rolname = current_user AS itself
        FROM pg_roles r WHERE pg_has_role(current_user, r.oid, 'MEMBER')
    ), events AS (
        SELECT c.oid, c.relowner FROM pg_class c WHERE c.oid = to_regclass('audit_events')
    )
    SELECT
        (SELECT CASE WHEN bool_or(itself) THEN 'itself' ELSE min(rolname) END
         FROM roles WHERE rolsuper),
        (SELECT CASE WHEN bool_or(itself) THEN 'itself' ELSE min(rolname) END
         FROM roles WHERE oid = events.relowner),
        ARRAY(
            SELECT p FROM unnest(ARRAY['UPDATE', 'DELETE', 'TRUNCATE']) WITH ORDINALITY AS t(p, n)
            WHERE EXISTS (SELECT FROM roles WHERE has_table_privilege(roles.oid, events.oid, p))
            ORDER BY n
        )
    FROM events
"""
REQUIRED = {
    "audit_events": (
        "id",
        "ts",
        "session_id",
        "identity",
        "client",
        "profile",
        "dry_run",
        "sql",
        "executed_sql",
        "rewrites",
        "decision",
        "refused_by",
        "code",
        "reason",
        "error",
        "cost_estimate",
        "rows_returned",
        "truncated",
        "masked_columns",
        "duration_ms",
        "trace",
    ),
    "session_usage": (
        "profile",
        "session_id",
        "queries",
        "total_cost",
        "rows_returned",
        "refusals",
        "updated_at",
    ),
    "caller_charges": (
        "profile",
        "caller",
        "ts",
        "queries",
        "total_cost",
        "rows_returned",
        "refusals",
    ),
    "audit_prunes": ("ts", "pruned_by", "older_than", "events", "sessions", "caller_charges"),
}
"""The tables and columns the schema makes, which a server that may not apply it checks for."""
NULLABLE = {("audit_events", "profile")}
"""Columns made nullable after their table was first made."""
_COLUMNS_OF = """
    SELECT a.attname, a.attnotnull FROM pg_attribute a
    WHERE a.attrelid = to_regclass(%s) AND a.attnum > 0 AND NOT a.attisdropped
"""


def _schema_problems(conn: psycopg.Connection[Any]) -> list[str]:
    """What the audit tables lack that this version of sql-warden needs. Asked of the
    catalog, so it needs no privileges on the tables."""
    problems = []
    for table, columns in REQUIRED.items():
        found = dict(conn.execute(_COLUMNS_OF, (table,)).fetchall())
        if not found:
            problems.append(f"there is no table {table}")
            continue
        missing = [column for column in columns if column not in found]
        if missing:
            problems.append(f"{table} has no column {', '.join(missing)}")
        problems += [
            f"{table}.{column} must allow NULL"
            for t, column in NULLABLE
            if t == table and found.get(column)
        ]
    return problems


def _current_role(conn: psycopg.Connection[Any]) -> str:
    row = conn.execute("SELECT current_user").fetchone()
    return str(row[0]) if row else "?"


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
