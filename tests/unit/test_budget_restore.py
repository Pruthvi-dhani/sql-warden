"""Budgets outlive the server: a session's usage is read back from the audit log."""

import datetime
import threading
from collections.abc import Collection
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from mcp import Client

from sql_warden.audit import AuditError, AuditEvent, MemoryAuditSink, usage_from
from sql_warden.cli import EXIT_REFUSED, cli
from sql_warden.config import BudgetConfig
from sql_warden.engines import CostEstimate, QueryFailed, Result
from sql_warden.models import Decision, RefusalCode
from sql_warden.server import create_server
from sql_warden.sessions import Usage
from sql_warden.warden import NOT_COUNTED, Warden
from tests.unit.conftest import AuditSinks, FakeEngine

SQL = "select id from products"
TEN_ROWS = Result(
    columns=("id",), rows=tuple((n,) for n in range(10)), truncated=False, duration_ms=1
)


def _event(decision: str = "allowed", **fields: Any) -> AuditEvent:
    defaults: dict[str, Any] = {
        "profile": "public",
        "sql": SQL,
        "decision": decision,
        "duration_ms": 1.0,
        "session_id": "s",
    }
    return AuditEvent(**{**defaults, **fields})


def _code(decision: Decision) -> RefusalCode | None:
    refused = decision.refused_by
    return refused.refusal.code if refused and refused.refusal else None


class TestUsageFromTheAuditLog:
    def test_a_query_that_ran_counts_with_its_cost_and_rows(self) -> None:
        events = [
            _event(cost_estimate=40.5, rows_returned=10),
            _event(cost_estimate=9.5, rows_returned=3),
        ]
        assert usage_from(events) == Usage(queries=2, total_cost=50.0, rows_returned=13)

    def test_a_query_the_database_failed_counts_without_rows(self) -> None:
        events = [_event("failed", cost_estimate=40, error="division by zero")]
        assert usage_from(events) == Usage(queries=1, total_cost=40)

    def test_a_dry_run_that_was_allowed_counts_for_nothing(self) -> None:
        assert usage_from([_event(dry_run=True, cost_estimate=40)]) == Usage()

    def test_refusals_count_dry_runs_included_and_their_estimates_dont(self) -> None:
        events = [
            _event("refused", code="NOT_A_SELECT"),
            _event("refused", code="TABLE_NOT_ALLOWED", dry_run=True),
            _event("refused", code="COST_TOO_HIGH", cost_estimate=1e10),
        ]
        assert usage_from(events) == Usage(refusals=3)

    def test_refusals_that_arent_counted(self) -> None:
        events = [_event("refused", code=str(code)) for code in RefusalCode]
        counted = usage_from(events, not_counted=NOT_COUNTED)
        assert counted == Usage(refusals=len(RefusalCode) - len(NOT_COUNTED))
        assert {str(code) for code in NOT_COUNTED} == {
            "BUDGET_EXHAUSTED",
            "COST_OVER_BUDGET",
            "BUDGET_UNAVAILABLE",
            "CATALOG_UNAVAILABLE",
            "COST_UNAVAILABLE",
            "AUDIT_UNAVAILABLE",
            "INTERNAL_ERROR",
        }

    def test_the_memory_sink_reads_one_session_under_one_profile(self) -> None:
        sink = MemoryAuditSink()
        for event in (
            _event(cost_estimate=10, rows_returned=1),
            _event(cost_estimate=10, rows_returned=1, session_id="other"),
            _event(cost_estimate=10, rows_returned=1, profile="admin"),
            _event(cost_estimate=10, rows_returned=1, session_id=None),
            _event("refused", code="NOT_A_SELECT"),
        ):
            sink.record(event)
        assert sink.usage("s", "public") == Usage(1, 10.0, 1, 1)
        assert sink.usage("s", "admin") == Usage(1, 10.0, 1, 0)
        assert sink.usage("nobody", "public") == Usage()

    def test_a_sink_that_is_down_cant_say(self) -> None:
        sink = MemoryAuditSink()
        sink.fail_with = AuditError("the audit database is unavailable: connection refused")
        with pytest.raises(AuditError, match="connection refused"):
            sink.usage("s", "public")


def _warden(audit: MemoryAuditSink, engine: FakeEngine | None = None, **limits: float) -> Warden:
    """A new server recording to the same audit log, as after a restart."""
    return Warden(engine or FakeEngine(), audit=audit, budget=BudgetConfig.model_validate(limits))


class TestARestartedServer:
    def test_a_session_keeps_what_it_had_used(self) -> None:
        audit = MemoryAuditSink()
        engine = FakeEngine(
            estimate=CostEstimate(40, est_rows=1, top_node="Seq Scan"), result=TEN_ROWS
        )
        before = _warden(audit, engine, max_queries=3)
        before.run(SQL, session_id="nightly")
        before.run(SQL, session_id="nightly")
        before.check("delete from products", session_id="nightly")
        before.check(SQL, session_id="nightly")  # an allowed dry run: free

        after = _warden(audit, engine, max_queries=3)
        assert after.budget_status("nightly").usage == before.budget_status("nightly").usage
        assert after.budget_status("nightly").usage == Usage(
            queries=2, total_cost=80, rows_returned=20, refusals=1
        )
        assert after.run(SQL, session_id="nightly").result is not None  # the third and last
        assert _code(after.run(SQL, session_id="nightly").decision) == RefusalCode.BUDGET_EXHAUSTED
        again = _warden(audit, engine, max_queries=3)
        assert _code(again.check(SQL, session_id="nightly")) == RefusalCode.BUDGET_EXHAUSTED

    def test_a_session_that_was_locked_out_stays_locked_out(self) -> None:
        audit = MemoryAuditSink()
        before = _warden(audit, max_refusals=2)
        before.run("delete from products", session_id="probing")
        before.check("select pg_sleep(1)", session_id="probing")
        after = _warden(audit, max_refusals=2)
        decision = after.run(SQL, session_id="probing").decision
        assert _code(decision) == RefusalCode.BUDGET_EXHAUSTED
        assert [entry.check for entry in decision.trace] == ["budget"]

    def test_what_is_restored_is_what_was_counted(self) -> None:
        # Every kind of request, then a restart: the two counts agree.
        audit = MemoryAuditSink()
        engine = FakeEngine(estimate=CostEstimate(40, est_rows=1, top_node="Seq Scan"))
        before = _warden(audit, engine, max_total_cost=100, max_refusals=50)
        before.run(SQL, session_id="s")
        engine.error = QueryFailed("division by zero")
        before.run(SQL, session_id="s")
        engine.error = None
        before.run(SQL, session_id="s")  # COST_OVER_BUDGET: the budget's own refusal
        before.run("select (1", session_id="s")
        before.check("delete from products", session_id="s")
        before.check(SQL, session_id="s")
        counted = before.budget_status("s").usage
        assert counted == Usage(queries=2, total_cost=80, rows_returned=1, refusals=2)
        assert _warden(audit, engine, max_total_cost=100).budget_status("s").usage == counted

    def test_other_sessions_and_profiles_dont_count(self) -> None:
        audit = MemoryAuditSink()
        _warden(audit, max_queries=1).run(SQL, session_id="one")
        admin = Warden(
            FakeEngine(), audit=audit, profile="admin", budget=BudgetConfig(max_queries=1)
        )
        assert admin.run(SQL, session_id="one").result is not None  # admin's own count
        after = _warden(audit, max_queries=1)
        assert after.run(SQL, session_id="two").result is not None
        assert after.run(SQL, session_id="one").result is None

    def test_a_new_servers_own_session_starts_from_nothing(self) -> None:
        audit = MemoryAuditSink()
        _warden(audit, max_queries=1).run(SQL)
        assert _warden(audit, max_queries=1).run(SQL).result is not None

    def test_requests_at_once_after_a_restart_still_cant_overspend(self) -> None:
        audit = MemoryAuditSink()
        engine = FakeEngine()
        before = _warden(audit, engine, max_queries=10)
        for _ in range(4):
            before.run(SQL, session_id="s")
        after = _warden(audit, engine, max_queries=10)
        start = threading.Barrier(12)

        def work() -> None:
            start.wait()
            for _ in range(3):
                after.run(SQL, session_id="s")

        threads = [threading.Thread(target=work) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(engine.executed) == 10


class Counting(MemoryAuditSink):
    """Counts how often it is asked for a session's usage."""

    def __init__(self) -> None:
        super().__init__()
        self.asked: list[str] = []

    def usage(self, session_id: str, profile: str, *, not_counted: Collection[str] = ()) -> Usage:
        self.asked.append(session_id)
        return super().usage(session_id, profile, not_counted=not_counted)


class TestReadingTheAuditLog:
    def test_a_profile_without_limits_never_asks(self) -> None:
        audit = Counting()
        warden = _warden(audit)
        warden.run(SQL)
        warden.check("delete from products", session_id="s")
        warden.budget_status("s")
        assert audit.asked == []

    def test_a_session_is_read_once(self) -> None:
        audit = Counting()
        warden = _warden(audit, max_queries=50)
        for _ in range(5):
            warden.run(SQL, session_id="s")
            warden.check(SQL, session_id="s")
        warden.run(SQL)
        assert audit.asked == ["s", warden.session_id]

    def test_usage_that_cant_be_read_refuses_the_query(self) -> None:
        class Unreadable(MemoryAuditSink):
            """Records, but can't be read back: say the role may insert and not select."""

            unreadable: AuditError | None = None

            def usage(self, session_id: str, profile: str, **options: Any) -> Usage:
                if self.unreadable is not None:
                    raise self.unreadable
                return super().usage(session_id, profile, **options)

        audit = Unreadable()
        engine = FakeEngine()
        warden = _warden(audit, engine, max_queries=5, max_refusals=1)
        audit.unreadable = AuditError("the audit database is unavailable: connection refused")
        for decision in (warden.run(SQL).decision, warden.check(SQL)):
            refused = decision.refused_by
            assert refused is not None
            assert refused.refusal is not None
            assert (refused.check, refused.refusal.code, refused.refusal.reason) == (
                "budget",
                RefusalCode.BUDGET_UNAVAILABLE,
                "this session's budget could not be checked: the audit database is "
                "unavailable: connection refused",
            )
        assert (engine.executed, engine.explained) == ([], [])
        assert [event.code for event in audit.events] == ["BUDGET_UNAVAILABLE"] * 2
        audit.unreadable = None
        # Back again: it is read now, and being unreadable was never counted as a refusal.
        assert warden.run(SQL).result is not None
        assert warden.budget_status().usage.refusals == 0

    def test_with_the_audit_database_down_that_is_what_the_refusal_says(self) -> None:
        # Nothing can be recorded either, and that is the reason nothing comes back.
        audit = MemoryAuditSink()
        engine = FakeEngine()
        warden = _warden(audit, engine, max_queries=5)
        audit.fail_with = AuditError("the audit database is unavailable: connection refused")
        decision = warden.run(SQL).decision
        assert [entry.check for entry in decision.trace] == ["budget", "audit"]
        assert _code(decision) == RefusalCode.AUDIT_UNAVAILABLE
        assert engine.executed == []

    def test_a_bug_while_reading_fails_closed_without_its_message(self) -> None:
        class Buggy(MemoryAuditSink):
            def usage(self, session_id: str, profile: str, **options: Any) -> Usage:
                raise ValueError("postgresql://user:secret@host/db")

        engine = FakeEngine()
        decision = _warden(Buggy(), engine, max_queries=5).run(SQL).decision
        refused = decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert refused.refusal.code == RefusalCode.BUDGET_UNAVAILABLE
        assert "unexpected ValueError" in refused.refusal.reason
        assert "secret" not in refused.refusal.reason
        assert engine.executed == []

    @pytest.mark.anyio
    @pytest.mark.parametrize("anyio_backend", ["asyncio"])
    async def test_budget_status_says_when_it_cant_be_read(self, anyio_backend: str) -> None:
        audit = MemoryAuditSink()
        audit.fail_with = AuditError("the audit database is unavailable: connection refused")
        async with Client(create_server(_warden(audit, max_queries=5))) as client:
            result = await client.call_tool("budget_status", {})
        assert result.is_error
        assert "this session's budget could not be read" in str(result.content)


POLICY = "version: 1\nbudgets:\n  max_queries: 2\n  max_refusals: 2\n"


class TestCli:
    def test_calls_with_the_same_session_share_a_budget(
        self, isolated_cli: Path, engines: list[FakeEngine], audit_sinks: AuditSinks
    ) -> None:
        (isolated_cli / "warden.yaml").write_text(POLICY)
        ran = [
            CliRunner().invoke(cli, ["query", "select 1", "--session", "nightly"]) for _ in range(3)
        ]
        assert [outcome.exit_code for outcome in ran] == [0, 0, EXIT_REFUSED]
        assert ran[1].output.splitlines()[-1] == (
            "session budget: 2 of 2 queries, 0 of 2 refusals used"
        )
        assert "BUDGET_EXHAUSTED: this session's budget is used up: it has run 2 of its 2" in (
            ran[2].output
        )
        assert sum(len(engine.executed) for engine in engines) == 2

    def test_calls_without_one_each_have_their_own(
        self, isolated_cli: Path, engines: list[FakeEngine], audit_sinks: AuditSinks
    ) -> None:
        (isolated_cli / "warden.yaml").write_text(POLICY)
        ran = [CliRunner().invoke(cli, ["query", "select 1"]) for _ in range(4)]
        assert [outcome.exit_code for outcome in ran] == [0, 0, 0, 0]

    def test_refusals_add_up_across_calls_too(
        self, isolated_cli: Path, engines: list[FakeEngine], audit_sinks: AuditSinks
    ) -> None:
        (isolated_cli / "warden.yaml").write_text(POLICY)
        for sql in ("delete from t", "select pg_sleep(1)"):
            CliRunner().invoke(cli, ["check", sql, "--session", "probing"])
        locked = CliRunner().invoke(cli, ["query", "select 1", "--session", "probing"])
        assert locked.exit_code == EXIT_REFUSED
        assert "2 of its requests were refused, and its limit is 2" in locked.output
        assert all(engine.executed == [] for engine in engines)

    def test_the_times_of_the_records_dont_matter(self, audit_sinks: AuditSinks) -> None:
        # A session's budget is for its whole life: yesterday's queries count.
        old = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=400)
        audit = MemoryAuditSink()
        audit.record(_event(profile="all", ts=old, cost_estimate=1, rows_returned=1))
        warden = Warden(FakeEngine(), audit=audit, budget=BudgetConfig(max_queries=1))
        assert _code(warden.run(SQL, session_id="s").decision) == RefusalCode.BUDGET_EXHAUSTED
