"""Budgets outlive the server, against real databases: usage read back from the audit log."""

import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from click.testing import CliRunner

from sql_warden.audit import AuditEvent, PostgresAuditSink, usage_from
from sql_warden.cli import EXIT_REFUSED, cli
from sql_warden.config import BudgetConfig
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.models import Decision, RefusalCode
from sql_warden.sessions import Usage
from sql_warden.warden import NOT_COUNTED, Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration


@pytest.fixture
def sink(audit_dsn: str) -> Iterator[PostgresAuditSink]:
    sink = PostgresAuditSink(audit_dsn)
    sink.ensure_schema()
    yield sink
    sink.close()


def _session() -> str:
    """A name no other test has used: the audit database is shared by them all."""
    return f"test-{uuid.uuid4().hex}"


def _event(session_id: str, decision: str = "allowed", **fields: Any) -> AuditEvent:
    defaults: dict[str, Any] = {
        "profile": "public",
        "sql": "select 1",
        "decision": decision,
        "duration_ms": 1.0,
        "session_id": session_id,
    }
    return AuditEvent(**{**defaults, **fields})


def _code(decision: Decision) -> RefusalCode | None:
    refused = decision.refused_by
    return refused.refusal.code if refused and refused.refusal else None


def test_the_sql_counts_what_the_rule_counts(sink: PostgresAuditSink) -> None:
    session = _session()
    events = [
        _event(session, cost_estimate=40.5, rows_returned=10),
        _event(session, cost_estimate=9.25, rows_returned=0),
        _event(session, "failed", cost_estimate=100, error="division by zero"),
        _event(session, dry_run=True, cost_estimate=7),
        _event(session, "refused", code="COST_TOO_HIGH", cost_estimate=1e10),
        _event(session, "refused", code="TABLE_NOT_ALLOWED", dry_run=True),
        *(_event(session, "refused", code=str(code)) for code in RefusalCode),
    ]
    for event in events:
        sink.record(event)
    expected = usage_from(events, not_counted=NOT_COUNTED)
    assert expected == Usage(
        queries=3,
        total_cost=149.75,
        rows_returned=10,
        refusals=2 + len(RefusalCode) - len(NOT_COUNTED),
    )
    assert sink.usage(session, "public", not_counted=NOT_COUNTED) == expected
    assert sink.usage(session, "public") == usage_from(events)  # every refusal counted


def test_only_that_session_under_that_profile(sink: PostgresAuditSink) -> None:
    session, other = _session(), _session()
    sink.record(_event(session, cost_estimate=10, rows_returned=1))
    sink.record(_event(other, cost_estimate=10, rows_returned=1))
    sink.record(_event(session, profile="admin", cost_estimate=10, rows_returned=5))
    assert sink.usage(session, "public") == Usage(1, 10.0, 1, 0)
    assert sink.usage(session, "admin") == Usage(1, 10.0, 5, 0)
    assert sink.usage(_session(), "public") == Usage()
    assert sink.usage(session[:-1], "public") == Usage()  # the whole name


def test_a_restarted_warden_finds_the_budget_still_used(
    warehouse: Warehouse, audit_dsn: str
) -> None:
    session = _session()
    budget = BudgetConfig(max_queries=3, max_refusals=5)

    def start() -> tuple[Warden, PostgresAuditSink]:
        audit = PostgresAuditSink(audit_dsn)
        audit.ensure_schema()
        engine = PostgresEngine(warehouse.reader_dsn, max_rows=5)
        return Warden(engine, audit=audit, budget=budget), audit

    first, first_audit = start()
    assert first.run("select id from products order by id", session_id=session).result is not None
    assert first.run("select sum(quantity) from orders", session_id=session).result is not None
    first.check("delete from orders", session_id=session)
    counted = first.budget_status(session).usage
    assert (counted.queries, counted.rows_returned, counted.refusals) == (2, 6, 1)
    assert counted.total_cost > 10_000  # the full scan of orders
    first_audit.close()  # the server stops

    second, second_audit = start()
    restored = second.budget_status(session).usage
    assert (restored.queries, restored.rows_returned, restored.refusals) == (2, 6, 1)
    assert restored.total_cost == pytest.approx(counted.total_cost)
    assert second.run("select 1", session_id=session).result is not None  # the third and last
    refused = second.run("select 1", session_id=session)
    assert _code(refused.decision) == RefusalCode.BUDGET_EXHAUSTED
    assert refused.decision.budget is not None
    assert refused.decision.budget.exhausted == "max_queries"
    # Its own session is new, and so is its budget.
    assert second.run("select 1").result is not None
    second_audit.close()

    third, third_audit = start()
    assert _code(third.check("select 1", session_id=session)) == RefusalCode.BUDGET_EXHAUSTED
    third_audit.close()


def test_cli_calls_with_one_session_share_a_budget(warehouse: Warehouse, tmp_path: Path) -> None:
    session = _session()
    policy = tmp_path / "warden.yaml"
    policy.write_text("version: 1\nbudgets:\n  max_queries: 2\n")
    env = {"SQL_WARDEN_DSN": warehouse.reader_dsn, "SQL_WARDEN_CONFIG": str(policy)}

    def query(*options: str) -> tuple[int, str]:
        outcome = CliRunner().invoke(cli, ["query", "select 1 as one", *options], env=env)
        return outcome.exit_code, outcome.output

    assert query("--session", session)[0] == 0
    code, output = query("--session", session)
    assert code == 0
    assert output.splitlines()[-1] == "session budget: 2 of 2 queries used"
    code, output = query("--session", session)
    assert code == EXIT_REFUSED
    assert "BUDGET_EXHAUSTED: this session's budget is used up: it has run 2 of its 2" in output
    assert query()[0] == 0  # a call without a session has its own
    assert query("--session", _session())[0] == 0


def test_usage_cant_be_read_from_an_audit_database_that_is_gone(audit_dsn: str) -> None:
    sink = PostgresAuditSink("postgresql://nobody:x@127.0.0.1:1/none", connect_timeout_s=1)
    with pytest.raises(Exception, match="could not read the session's usage") as excinfo:
        sink.usage("s", "public")
    assert ":x@" not in str(excinfo.value)
    # And without the table, as before sql-warden has ever started against the database.
    fresh = PostgresAuditSink(audit_dsn)
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute("ALTER TABLE IF EXISTS audit_events RENAME TO audit_events_aside")
    try:
        with pytest.raises(Exception, match="could not read the session's usage"):
            fresh.usage("s", "public")
    finally:
        with psycopg.connect(audit_dsn, autocommit=True) as conn:
            conn.execute("ALTER TABLE IF EXISTS audit_events_aside RENAME TO audit_events")
        fresh.close()
