"""PostgresAuditSink against its own Postgres, as in production: separate from the warehouse."""

import datetime
import threading
import uuid
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row

from sql_warden.audit import AuditError, AuditEvent, PostgresAuditSink

pytestmark = pytest.mark.integration

TRACE = (
    {"check": "parse", "passed": True, "code": None, "reason": None, "duration_ms": 0.4},
    {
        "check": "access",
        "passed": False,
        "code": "TABLE_NOT_ALLOWED",
        "reason": "table public.employee_salaries is not available to profile public",
        "duration_ms": 0.2,
    },
)


@pytest.fixture
def sink(audit_dsn: str) -> Iterator[PostgresAuditSink]:
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS audit_events")
    sink = PostgresAuditSink(audit_dsn)
    sink.ensure_schema()
    yield sink
    sink.close()


def _rows(audit_dsn: str) -> list[dict[str, Any]]:
    with psycopg.connect(audit_dsn, row_factory=dict_row) as conn:
        return conn.execute("SELECT * FROM audit_events ORDER BY ts").fetchall()


def test_a_refusal_round_trips(sink: PostgresAuditSink, audit_dsn: str) -> None:
    event = AuditEvent(
        profile="public",
        sql="select * from employee_salaries",
        decision="refused",
        duration_ms=1.25,
        trace=TRACE,
        refused_by="access",
        code="TABLE_NOT_ALLOWED",
        reason="table public.employee_salaries is not available to profile public",
        session_id="s-1",
        client="claude-code 2.1",
    )
    sink.record(event)
    (row,) = _rows(audit_dsn)
    assert row == {
        "id": event.id,
        "ts": event.ts,
        "session_id": "s-1",
        "client": "claude-code 2.1",
        "profile": "public",
        "dry_run": False,
        "sql": "select * from employee_salaries",
        "executed_sql": None,
        "rewrites": [],
        "decision": "refused",
        "refused_by": "access",
        "code": "TABLE_NOT_ALLOWED",
        "reason": "table public.employee_salaries is not available to profile public",
        "error": None,
        "cost_estimate": None,
        "rows_returned": None,
        "truncated": None,
        "masked_columns": [],
        "duration_ms": 1.25,
        "trace": list(TRACE),
        "identity": None,
    }


def test_a_caller_turned_away_has_no_profile(sink: PostgresAuditSink, audit_dsn: str) -> None:
    sink.record(
        AuditEvent(
            profile=None,
            sql="",
            decision="refused",
            duration_ms=0.5,
            refused_by="auth",
            code="NO_PROFILE",
            reason="the token gives a profile this server doesn't have",
            identity="oidc:ana",
        )
    )
    (row,) = _rows(audit_dsn)
    assert (row["profile"], row["identity"], row["code"]) == (None, "oidc:ana", "NO_PROFILE")


def test_an_audit_database_from_before_auth_is_brought_up_to_date(audit_dsn: str) -> None:
    # The table as it was made before identity existed: profile still NOT NULL.
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS audit_events")
        conn.execute(
            """
            CREATE TABLE audit_events (
                id uuid PRIMARY KEY, ts timestamptz NOT NULL, session_id text, client text,
                profile text NOT NULL, dry_run boolean NOT NULL, sql text NOT NULL,
                executed_sql text, rewrites text[] NOT NULL DEFAULT '{}',
                decision text NOT NULL, refused_by text, code text, reason text, error text,
                cost_estimate double precision, rows_returned integer, truncated boolean,
                masked_columns text[] NOT NULL DEFAULT '{}', duration_ms double precision
                NOT NULL, trace jsonb NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO audit_events (id, ts, profile, dry_run, sql, decision, duration_ms, "
            "trace) VALUES (gen_random_uuid(), now(), 'public', false, 'select 1', 'allowed', "
            "1, '[]')"
        )
    sink = PostgresAuditSink(audit_dsn)
    try:
        sink.ensure_schema()
        sink.record(AuditEvent(profile=None, sql="", decision="refused", duration_ms=1, code="X"))
    finally:
        sink.close()
    rows = _rows(audit_dsn)
    assert [(row["profile"], row["identity"]) for row in rows] == [("public", None), (None, None)]


def test_an_allowed_run_round_trips(sink: PostgresAuditSink, audit_dsn: str) -> None:
    sink.record(
        AuditEvent(
            profile="admin",
            sql="select id from orders",
            decision="allowed",
            duration_ms=12.5,
            executed_sql="SELECT id FROM public.orders LIMIT 101",
            rewrites=("added LIMIT 101 (row cap 100 + 1 to detect truncation)",),
            rows_returned=100,
            truncated=True,
            cost_estimate=1234.5,
            masked_columns=("customers.ssn",),
        )
    )
    (row,) = _rows(audit_dsn)
    assert row["rewrites"] == ["added LIMIT 101 (row cap 100 + 1 to detect truncation)"]
    assert (row["rows_returned"], row["truncated"], row["cost_estimate"]) == (100, True, 1234.5)
    assert row["masked_columns"] == ["customers.ssn"]
    assert row["ts"].tzinfo is not None


def test_the_schema_can_be_applied_again(sink: PostgresAuditSink, audit_dsn: str) -> None:
    sink.record(AuditEvent(profile="all", sql="select 1", decision="allowed", duration_ms=1))
    sink.ensure_schema()
    assert len(_rows(audit_dsn)) == 1  # nothing dropped or recreated


def test_servers_starting_together_set_up_the_schema_once(audit_dsn: str) -> None:
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS audit_events")
    errors: list[Exception] = []

    def start() -> None:
        sink = PostgresAuditSink(audit_dsn)
        try:
            sink.ensure_schema()
        except Exception as exc:  # pragma: no cover - the failure being tested for
            errors.append(exc)
        finally:
            sink.close()

    threads = [threading.Thread(target=start) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []


def test_threads_share_one_sink(sink: PostgresAuditSink, audit_dsn: str) -> None:
    def write(n: int) -> None:
        for i in range(10):
            sink.record(
                AuditEvent(profile="all", sql=f"select {n}{i}", decision="allowed", duration_ms=1)
            )

    threads = [threading.Thread(target=write, args=(n,)) for n in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(_rows(audit_dsn)) == 50


def test_a_broken_connection_is_replaced(sink: PostgresAuditSink, audit_dsn: str) -> None:
    sink.record(AuditEvent(profile="all", sql="select 1", decision="allowed", duration_ms=1))
    # The audit database drops the sink's connection, as a restart would.
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = current_database() AND pid <> pg_backend_pid()"
        )
    sink.record(AuditEvent(profile="all", sql="select 2", decision="allowed", duration_ms=1))
    assert [row["sql"] for row in _rows(audit_dsn)] == ["select 1", "select 2"]


def test_an_unreachable_database_is_an_audit_error() -> None:
    sink = PostgresAuditSink("postgresql://nobody:secret@127.0.0.1:1/none", connect_timeout_s=1)
    with pytest.raises(AuditError, match="could not record the audit event") as caught:
        sink.record(AuditEvent(profile="all", sql="select 1", decision="allowed", duration_ms=1))
    assert "secret" not in str(caught.value)


def test_a_missing_table_is_an_audit_error(audit_dsn: str) -> None:
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS audit_events")
    sink = PostgresAuditSink(audit_dsn)
    with pytest.raises(AuditError, match='relation "audit_events" does not exist'):
        sink.record(AuditEvent(profile="all", sql="select 1", decision="allowed", duration_ms=1))
    sink.close()


def test_the_database_rejects_an_unknown_decision(sink: PostgresAuditSink) -> None:
    bad = AuditEvent(profile="all", sql="select 1", decision="maybe", duration_ms=1)  # type: ignore[arg-type]
    with pytest.raises(AuditError, match="audit_events_decision_check"):
        sink.record(bad)


def test_ids_are_unique(sink: PostgresAuditSink) -> None:
    event = AuditEvent(
        profile="all",
        sql="select 1",
        decision="allowed",
        duration_ms=1,
        id=uuid.UUID(int=1),
        ts=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
    )
    sink.record(event)
    with pytest.raises(AuditError, match="duplicate key"):
        sink.record(event)
