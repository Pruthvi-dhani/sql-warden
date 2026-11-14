"""Budgets kept in the audit database, shared by every server recording there.

Each "replica" here is a Warden with its own audit sink and session store, so its own
connections, as two processes behind a load balancer would have. They charge the same
session, and the same caller, from many threads at once.
"""

import threading
from pathlib import Path

import psycopg
import pytest
from click.testing import CliRunner

from sql_warden.audit import AuditEvent, Decision, PostgresAuditSink, PostgresSessionStore
from sql_warden.cli import EXIT_REFUSED, cli
from sql_warden.config import BudgetConfig, IdentityBudgetConfig
from sql_warden.engines import CostEstimate
from sql_warden.models import RefusalCode
from sql_warden.sessions import CallerCharge, Usage
from sql_warden.warden import NOT_COUNTED, Warden
from tests.integration.conftest import Warehouse
from tests.unit.conftest import FakeEngine

pytestmark = pytest.mark.integration

SQL = "select id from products"


@pytest.fixture
def fresh(audit_dsn: str) -> None:
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS audit_events, session_usage, caller_charges")
    sink = PostgresAuditSink(audit_dsn)
    sink.ensure_schema()
    sink.close()


class Replica:
    """One server: its own connections to the shared audit database."""

    def __init__(
        self,
        audit_dsn: str,
        budget: BudgetConfig | None = None,
        identity_budget: IdentityBudgetConfig | None = None,
        engine: FakeEngine | None = None,
    ) -> None:
        self.audit = PostgresAuditSink(audit_dsn)
        self.store = self.audit.session_store("support", not_counted=NOT_COUNTED)
        self.warden = Warden(
            engine or FakeEngine(),
            audit=self.audit,
            profile="support",
            budget=budget,
            identity_budget=identity_budget,
            sessions=self.store,
        )

    def close(self) -> None:
        self.store.close()
        self.audit.close()


def _hammer(
    replicas: list[Replica], *, threads: int, each: int, session: str | None, identity: str | None
) -> list[bool]:
    """Every replica runs `threads` threads of `each` queries; whether each ran."""
    ran: list[bool] = []
    lock = threading.Lock()

    def spend(replica: Replica, n: int) -> None:
        for i in range(each):
            outcome = replica.warden.run(
                SQL,
                session_id=session or f"s-{id(replica)}-{n}-{i}",
                identity=identity,
            )
            with lock:
                ran.append(outcome.result is not None)

    workers = [
        threading.Thread(target=spend, args=(replica, n))
        for replica in replicas
        for n in range(threads)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    return ran


def _scalar(audit_dsn: str, sql: str) -> object:
    with psycopg.connect(audit_dsn) as conn:
        row = conn.execute(sql).fetchone()
    assert row is not None
    return row[0]


def test_two_replicas_never_overspend_one_session(fresh: None, audit_dsn: str) -> None:
    replicas = [Replica(audit_dsn, BudgetConfig(max_queries=30)) for _ in range(2)]
    try:
        ran = _hammer(replicas, threads=6, each=8, session="shared", identity=None)
    finally:
        for replica in replicas:
            replica.close()
    assert (len(ran), ran.count(True)) == (96, 30)
    assert _scalar(audit_dsn, "SELECT queries FROM session_usage WHERE session_id = 'shared'") == 30
    allowed = "SELECT count(*) FROM audit_events WHERE decision = 'allowed'"
    assert _scalar(audit_dsn, allowed) == 30


def test_nor_one_caller_across_sessions(fresh: None, audit_dsn: str) -> None:
    caller = IdentityBudgetConfig(max_queries=25)
    replicas = [Replica(audit_dsn, identity_budget=caller) for _ in range(2)]
    try:
        # Every query in a session of its own: only the caller's budget holds them.
        ran = _hammer(replicas, threads=5, each=8, session=None, identity="web-agent")
        other = replicas[0].warden.run(SQL, session_id="elsewhere", identity="other-agent")
    finally:
        for replica in replicas:
            replica.close()
    assert ran.count(True) == 25
    assert other.result is not None  # another caller is not held to it
    counted = "SELECT sum(queries) FROM caller_charges WHERE caller = 'web-agent'"
    assert _scalar(audit_dsn, counted) == 25


def test_a_charge_that_doesnt_fit_changes_nothing(fresh: None, audit_dsn: str) -> None:
    costly = FakeEngine(estimate=CostEstimate(40, est_rows=1, top_node="Seq Scan"))
    replica = Replica(audit_dsn, BudgetConfig(max_total_cost=100), engine=costly)
    try:
        for _ in range(2):
            replica.warden.run(SQL, session_id="s")
        refused = replica.warden.run(SQL, session_id="s").decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert refused.refusal.code == RefusalCode.COST_OVER_BUDGET
        # Not the third query, nor its refusal: one the budget refuses isn't counted.
        assert replica.store.usage("s") == Usage(queries=2, total_cost=80, rows_returned=2)
    finally:
        replica.close()


def test_a_session_from_before_the_store_starts_from_the_audit_log(
    fresh: None, audit_dsn: str
) -> None:
    sink = PostgresAuditSink(audit_dsn)
    decisions: tuple[Decision, ...] = ("allowed", "allowed", "refused")
    for decision in decisions:
        sink.record(
            AuditEvent(
                profile="support",
                sql="select 1",
                decision=decision,
                duration_ms=1,
                session_id="nightly-report",
                cost_estimate=5.0 if decision == "allowed" else None,
                code="TABLE_NOT_ALLOWED" if decision == "refused" else None,
            )
        )
    sink.close()
    store = PostgresSessionStore(audit_dsn, profile="support", not_counted=NOT_COUNTED)
    try:
        assert store.usage("nightly-report") == Usage(queries=2, total_cost=10, refusals=1)
        charge = store.charge(
            "nightly-report", Usage(queries=1), within=BudgetConfig(max_queries=3)
        )
        assert charge.usage == Usage(queries=3, total_cost=10, refusals=1)
        assert not store.charge(
            "nightly-report", Usage(queries=1), within=BudgetConfig(max_queries=3)
        ).made
        # Another profile's session of the same name is another session.
        other = PostgresSessionStore(audit_dsn, profile="admin")
        assert other.usage("nightly-report") == Usage()
        other.close()
    finally:
        store.close()


def test_use_older_than_the_window_stops_counting_and_is_forgotten(
    fresh: None, audit_dsn: str
) -> None:
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO caller_charges (profile, caller, ts, queries) VALUES "
            "('support', 'bot', now() - interval '25 hours', 7), "
            "('support', 'bot', now() - interval '23 hours', 2)"
        )
    store = PostgresSessionStore(audit_dsn, profile="support")
    day = 24 * 3600.0
    try:
        assert store.caller_usage("bot", day) == Usage(queries=2)
        assert store.caller_usage("bot", 2 * day) == Usage(queries=9)
        bot = CallerCharge("bot", day, within=BudgetConfig(max_queries=3))
        assert store.charge("s", Usage(queries=1), caller=bot).caller_usage == Usage(queries=3)
        assert not store.charge("s", Usage(queries=1), caller=bot).made
    finally:
        store.close()
    # The charge older than the window was deleted when the caller was charged.
    assert _scalar(audit_dsn, "SELECT count(*) FROM caller_charges WHERE caller = 'bot'") == 2


def test_a_store_that_cant_be_reached_fails_closed(fresh: None, audit_dsn: str) -> None:
    unreachable = PostgresSessionStore(
        "postgresql://nobody:hunter2@127.0.0.1:1/audit", profile="support", connect_timeout_s=1
    )
    warden = Warden(
        FakeEngine(),
        audit=PostgresAuditSink(audit_dsn),
        budget=BudgetConfig(max_queries=5),
        sessions=unreachable,
    )
    outcome = warden.run(SQL)
    refused = outcome.decision.refused_by
    assert refused is not None
    assert refused.refusal is not None
    assert refused.refusal.code == RefusalCode.BUDGET_UNAVAILABLE
    assert "hunter2" not in refused.refusal.reason
    assert outcome.result is None


def test_the_cli_keeps_budgets_in_the_audit_database(
    fresh: None, warehouse: Warehouse, audit_dsn: str, tmp_path: Path
) -> None:
    policy = tmp_path / "warden.yaml"
    policy.write_text(
        f"version: 1\nwarehouse:\n  dsn: {warehouse.reader_dsn}\naudit:\n  dsn: {audit_dsn}\n"
        "budgets:\n  max_queries: 1\n"
    )

    def query() -> int:
        args = ["--config", str(policy), "query", "select 1", "--session", "shared-run"]
        return CliRunner().invoke(cli, args).exit_code

    assert query() == 0
    assert query() == EXIT_REFUSED
    row = "SELECT queries, refusals FROM session_usage WHERE session_id = 'shared-run'"
    with psycopg.connect(audit_dsn) as conn:
        assert conn.execute(row).fetchone() == (1, 0)
