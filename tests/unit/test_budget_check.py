"""The budget check: what a session has used, against what its profile lets a session use."""

import threading
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from mcp import Client

from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import EXIT_REFUSED, cli
from sql_warden.config import BudgetConfig, ConfigError, parse_config
from sql_warden.engines import (
    CostEstimate,
    EngineUnavailable,
    QueryFailed,
    Result,
)
from sql_warden.models import Decision, Refusal, RefusalCode
from sql_warden.pipeline import CheckContext
from sql_warden.profiles import select_profile
from sql_warden.render import format_decision
from sql_warden.server import create_server, describe
from sql_warden.sessions import MemorySessionStore, Usage
from sql_warden.warden import Warden
from tests.unit.conftest import AuditSinks, FakeEngine

SQL = "select id from products"
TEN_ROWS = Result(
    columns=("id",), rows=tuple((n,) for n in range(10)), truncated=False, duration_ms=1
)


def _costing(cost: float, **settings: Any) -> FakeEngine:
    return FakeEngine(estimate=CostEstimate(cost, est_rows=1, top_node="Seq Scan"), **settings)


def _warden(engine: FakeEngine | None = None, **limits: float) -> Warden:
    return Warden(
        engine or FakeEngine(),
        audit=MemoryAuditSink(),
        budget=BudgetConfig.model_validate(limits),
    )


def _refusal(decision: Decision) -> tuple[str, RefusalCode, str]:
    refused = decision.refused_by
    assert refused is not None
    assert refused.refusal is not None
    return refused.check, refused.refusal.code, refused.refusal.reason


def _checks(decision: Decision) -> list[str]:
    return [entry.check for entry in decision.trace]


class TestWithoutLimits:
    def test_there_is_no_budget_check(self) -> None:
        warden = _warden()
        outcome = warden.run(SQL)
        assert _checks(outcome.decision) == ["parse", "shape", "cost"]
        assert outcome.decision.budget is None
        assert "budget" not in describe(outcome.decision, outcome).model_dump(exclude_none=True)

    def test_usage_is_counted_all_the_same(self) -> None:
        warden = _warden(_costing(40, result=TEN_ROWS))
        warden.run(SQL)
        warden.run(SQL)
        warden.run("delete from products")
        warden.check("select pg_sleep(1)")
        assert warden.budget_status().usage == Usage(
            queries=2, total_cost=80, rows_returned=20, refusals=2
        )


class TestQueries:
    def test_the_last_query_runs_and_the_next_is_refused(self) -> None:
        engine = FakeEngine()
        warden = _warden(engine, max_queries=2)
        assert warden.run(SQL).result is not None
        assert warden.run(SQL).result is not None
        outcome = warden.run(SQL)
        assert outcome.result is None
        assert _refusal(outcome.decision) == (
            "budget",
            RefusalCode.BUDGET_EXHAUSTED,
            "this session's budget is used up: it has run 2 of its 2 queries. Nothing more "
            "runs in this session",
        )
        assert len(engine.executed) == 2

    def test_a_session_that_is_used_up_gets_no_other_check(self) -> None:
        # Not even a parse: it learns nothing more, and the planner is left alone.
        engine = FakeEngine()
        warden = _warden(engine, max_queries=1)
        warden.run(SQL)
        explained = len(engine.explained)
        for decision in (warden.run("select (1").decision, warden.check(SQL)):
            assert _checks(decision) == ["budget"]
            assert _refusal(decision)[1] == RefusalCode.BUDGET_EXHAUSTED
        assert len(engine.explained) == explained

    def test_the_budget_is_checked_last_once_the_cost_is_known(self) -> None:
        decision = _warden(max_queries=5).run(SQL).decision
        assert _checks(decision) == ["parse", "shape", "cost", "budget"]
        assert decision.allowed

    def test_a_dry_run_spends_nothing(self) -> None:
        warden = _warden(_costing(40), max_queries=2, max_total_cost=100)
        for _ in range(10):
            decision = warden.check(SQL)
            assert decision.allowed
            assert _checks(decision)[-1] == "budget"
        assert warden.budget_status().usage == Usage()

    def test_a_query_another_check_refuses_isnt_spent(self) -> None:
        warden = _warden(max_queries=1)
        warden.run("delete from products")
        warden.run("select pg_sleep(1)")
        assert warden.budget_status().usage == Usage(refusals=2)
        assert warden.run(SQL).result is not None

    def test_a_query_the_database_fails_to_run_is_spent(self) -> None:
        warden = _warden(_costing(40, error=QueryFailed("division by zero")), max_queries=1)
        assert warden.run(SQL).error is not None
        assert warden.budget_status().usage == Usage(queries=1, total_cost=40)
        assert _refusal(warden.run(SQL).decision)[1] == RefusalCode.BUDGET_EXHAUSTED

    def test_a_check_given_to_the_warden_runs_before_the_query_is_spent(self) -> None:
        class Never:
            name = "never"

            def run(self, ctx: CheckContext) -> Refusal | None:
                return Refusal(RefusalCode.INTERNAL_ERROR, "no")

        warden = Warden(
            FakeEngine(),
            audit=MemoryAuditSink(),
            checks=[Never()],
            budget=BudgetConfig(max_queries=1),
        )
        assert _checks(warden.run(SQL).decision) == ["parse", "shape", "cost", "never"]
        assert warden.budget_status().usage == Usage()


class TestTotalCost:
    def test_queries_run_until_the_next_doesnt_fit(self) -> None:
        engine = _costing(40)
        warden = _warden(engine, max_total_cost=100)
        assert warden.run(SQL).result is not None
        assert warden.run(SQL).result is not None
        outcome = warden.run(SQL)
        assert _refusal(outcome.decision) == (
            "budget",
            RefusalCode.COST_OVER_BUDGET,
            "the planner estimates this query at 40, more than the 20 this session has left "
            "of the 100 it may spend. A cheaper query may still fit",
        )
        assert len(engine.executed) == 2
        assert warden.budget_status().usage == Usage(queries=2, total_cost=80, rows_returned=2)

    def test_a_cheaper_query_still_fits(self) -> None:
        engine = _costing(40)
        warden = _warden(engine, max_total_cost=100)
        warden.run(SQL)
        warden.run(SQL)
        engine.estimate = CostEstimate(20, est_rows=1, top_node="Result")
        assert warden.run(SQL).result is not None  # exactly what was left
        assert warden.budget_status().usage.total_cost == 100

    def test_once_it_is_all_spent_the_session_is_done(self) -> None:
        warden = _warden(_costing(50), max_total_cost=100)
        warden.run(SQL)
        warden.run(SQL)
        decision = warden.run("select 1").decision
        assert _checks(decision) == ["budget"]
        assert _refusal(decision)[1:] == (
            RefusalCode.BUDGET_EXHAUSTED,
            "this session's budget is used up: its queries have cost 100 of the 100 it may "
            "spend. Nothing more runs in this session",
        )

    def test_a_dry_run_is_told_it_wouldnt_fit(self) -> None:
        warden = _warden(_costing(40), max_total_cost=100)
        warden.run(SQL)
        warden.run(SQL)
        decision = warden.check(SQL)
        assert _refusal(decision)[1] == RefusalCode.COST_OVER_BUDGET
        assert decision.sql is None
        assert decision.cost is not None  # the estimate it was held against

    def test_the_refusal_keeps_the_estimate(self) -> None:
        warden = _warden(_costing(400), max_total_cost=100)
        decision = warden.run(SQL).decision
        assert _refusal(decision)[1] == RefusalCode.COST_OVER_BUDGET
        assert decision.cost is not None
        assert decision.cost.total_cost == 400


class TestRowsReturned:
    def test_the_query_that_passes_the_limit_comes_back_and_the_next_is_refused(self) -> None:
        engine = FakeEngine(result=TEN_ROWS)
        warden = _warden(engine, max_rows_returned=15)
        assert warden.run(SQL).result is not None
        second = warden.run(SQL)  # 20 rows by now: rows are only known once it has run
        assert second.result is not None
        assert len(second.result.rows) == 10
        assert _refusal(warden.run(SQL).decision)[1:] == (
            RefusalCode.BUDGET_EXHAUSTED,
            "this session's budget is used up: it has been returned 20 rows, and its limit "
            "is 15. Nothing more runs in this session",
        )
        assert len(engine.executed) == 2


class TestRefusals:
    def test_refusals_lock_the_session_dry_runs_included(self) -> None:
        engine = FakeEngine()
        warden = _warden(engine, max_refusals=3)
        warden.run("delete from products")
        warden.check("select pg_sleep(1)")
        assert warden.run(SQL).result is not None  # two refusals: still open
        warden.check("select (1")
        for decision in (warden.run(SQL).decision, warden.check(SQL)):
            assert _refusal(decision) == (
                "budget",
                RefusalCode.BUDGET_EXHAUSTED,
                "this session's budget is used up: 3 of its requests were refused, and its "
                "limit is 3. Nothing more runs in this session",
            )
        assert len(engine.executed) == 1

    def test_the_budgets_own_refusals_dont_count(self) -> None:
        warden = _warden(_costing(400), max_refusals=2, max_total_cost=100)
        for _ in range(5):
            assert _refusal(warden.run(SQL).decision)[1] == RefusalCode.COST_OVER_BUDGET
        assert warden.budget_status().usage == Usage()

    def test_trouble_that_isnt_the_callers_doesnt_count(self) -> None:
        down = FakeEngine(explain_error=EngineUnavailable("connection refused"))
        warden = _warden(down, max_refusals=2)
        for _ in range(5):
            assert _refusal(warden.run(SQL).decision)[1] == RefusalCode.COST_UNAVAILABLE
        assert warden.budget_status().usage == Usage()

    def test_a_query_the_planner_rejects_counts(self) -> None:
        warden = _warden(FakeEngine(explain_error=QueryFailed("division by zero")), max_refusals=2)
        warden.run("select 1 / 0")
        assert warden.budget_status().usage == Usage(refusals=1)


class TestSessions:
    def test_each_session_has_its_own_budget(self) -> None:
        warden = _warden(max_queries=1)
        assert warden.run(SQL, session_id="a").result is not None
        assert warden.run(SQL, session_id="b").result is not None
        assert warden.run(SQL).result is not None  # the Warden's own
        for session_id in ("a", "b", None):
            assert warden.run(SQL, session_id=session_id).result is None
        assert warden.budget_status("a").usage == Usage(queries=1, total_cost=1.0, rows_returned=1)

    def test_wardens_dont_share_usage_unless_given_one_store(self) -> None:
        store = MemorySessionStore()
        budget = BudgetConfig(max_queries=1)
        first = Warden(FakeEngine(), audit=MemoryAuditSink(), budget=budget, sessions=store)
        second = Warden(FakeEngine(), audit=MemoryAuditSink(), budget=budget, sessions=store)
        assert first.run(SQL, session_id="shared").result is not None
        assert second.run(SQL, session_id="shared").result is None
        assert _warden(max_queries=1).run(SQL, session_id="shared").result is not None

    def test_requests_at_once_cant_spend_the_same_last_query(self) -> None:
        engine = FakeEngine()
        warden = _warden(engine, max_queries=10)
        start = threading.Barrier(16)
        ran = []

        def work() -> None:
            start.wait()
            for _ in range(5):
                if warden.run(SQL).result is not None:
                    ran.append(1)

        threads = [threading.Thread(target=work) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(ran) == 10
        assert len(engine.executed) == 10
        assert warden.budget_status().usage.queries == 10


class TestFailClosed:
    def test_a_store_that_fails_refuses_the_query(self) -> None:
        class Broken(MemorySessionStore):
            def usage(self, session_id: str) -> Usage:
                raise RuntimeError("store is down")

        engine = FakeEngine()
        warden = Warden(
            engine,
            audit=MemoryAuditSink(),
            budget=BudgetConfig(max_queries=5),
            sessions=Broken(),
        )
        decision = warden.run(SQL).decision
        assert _refusal(decision)[:2] == ("budget", RefusalCode.INTERNAL_ERROR)
        assert engine.executed == []

    def test_a_query_that_cant_be_counted_doesnt_run_even_without_limits(self) -> None:
        class Broken(MemorySessionStore):
            def charge(self, session_id: str, spent: Usage, **options: Any) -> Any:
                raise RuntimeError("store is down")

        engine = FakeEngine()
        warden = Warden(engine, audit=MemoryAuditSink(), sessions=Broken())
        decision = warden.run(SQL).decision
        assert _refusal(decision)[:2] == ("budget", RefusalCode.INTERNAL_ERROR)
        assert engine.executed == []

    def test_rows_that_cant_be_counted_are_withheld(self) -> None:
        class Broken(MemorySessionStore):
            def charge(self, session_id: str, spent: Usage, **options: Any) -> Any:
                if spent.rows_returned:
                    raise RuntimeError("store is down")
                return super().charge(session_id, spent, **options)

        warden = Warden(FakeEngine(), audit=MemoryAuditSink(), sessions=Broken())
        outcome = warden.run(SQL)
        assert outcome.result is None
        assert str(outcome.error) == (
            "the rows could not be counted against the session's budget, so they are withheld"
        )
        assert isinstance(warden.audit, MemoryAuditSink)
        assert [event.decision for event in warden.audit.events] == ["failed"]


class TestWhereItShows:
    def test_the_decision_says_what_the_session_has_used(self) -> None:
        warden = _warden(_costing(40, result=TEN_ROWS), max_queries=5, max_refusals=3)
        decision = warden.run(SQL).decision
        assert decision.budget is not None
        assert decision.budget.usage == Usage(queries=1, total_cost=40, rows_returned=10)
        refused = warden.check("delete from products")
        assert refused.budget is not None
        assert refused.budget.usage.refusals == 1

    def test_the_response(self) -> None:
        warden = _warden(_costing(40.004, result=TEN_ROWS), max_queries=2, max_total_cost=100)
        outcome = warden.run(SQL)
        budget = describe(outcome.decision, outcome).model_dump(exclude_none=True)["budget"]
        assert budget == {
            "queries": {"used": 1, "limit": 2, "remaining": 1},
            "total_cost": {"used": 40.0, "limit": 100, "remaining": 60.0},
            "rows_returned": {"used": 10},
            "refusals": {"used": 0},
        }
        outcome = warden.run(SQL)
        budget = describe(outcome.decision, outcome).model_dump(exclude_none=True)["budget"]
        assert budget["exhausted"] == "max_queries"
        assert budget["queries"] == {"used": 2, "limit": 2, "remaining": 0}

    def test_the_cli_text(self) -> None:
        warden = _warden(_costing(1234.5), max_queries=20, max_total_cost=50_000, max_refusals=5)
        warden.run(SQL)
        text = format_decision(warden.check(SQL), dry_run=True)
        assert "  session budget: 1 of 20 queries, 1,234 of 50,000 cost, 0 of 5 refusals used" in (
            text.splitlines()
        )
        assert "✓ budget" in text

    def test_the_audit_record(self) -> None:
        warden = _warden(max_queries=1)
        warden.run(SQL)
        warden.run(SQL)
        assert isinstance(warden.audit, MemoryAuditSink)
        event = warden.audit.events[-1]
        assert (event.decision, event.refused_by, event.code) == (
            "refused",
            "budget",
            "BUDGET_EXHAUSTED",
        )
        assert event.trace[-1]["check"] == "budget"


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
class TestMcp:
    async def test_budget_status(self, anyio_backend: str) -> None:
        warden = _warden(_costing(40, result=TEN_ROWS), max_queries=2, max_refusals=5)
        async with Client(create_server(warden)) as client:
            before = (await client.call_tool("budget_status", {})).structured_content
            ran = (await client.call_tool("run_query", {"sql": SQL})).structured_content
            await client.call_tool("check_query", {"sql": "delete from products"})
            after = (await client.call_tool("budget_status", {})).structured_content
        assert before is not None
        assert ran is not None
        assert after is not None
        assert before == {
            "profile": "all",
            "session_id": warden.session_id,
            "budget": {
                "queries": {"used": 0, "limit": 2, "remaining": 2},
                "total_cost": {"used": 0, "limit": None, "remaining": None},
                "rows_returned": {"used": 0, "limit": None, "remaining": None},
                "refusals": {"used": 0, "limit": 5, "remaining": 5},
                "exhausted": None,
                "caller": None,  # no token, so no caller's budget
            },
        }
        assert ran["budget"]["queries"] == {"used": 1, "limit": 2, "remaining": 1}
        assert after["budget"]["queries"]["used"] == 1
        assert after["budget"]["total_cost"]["used"] == 40
        assert after["budget"]["rows_returned"]["used"] == 10
        assert after["budget"]["refusals"] == {"used": 1, "limit": 5, "remaining": 4}

    async def test_asking_is_free_and_works_on_a_session_that_is_used_up(
        self, anyio_backend: str
    ) -> None:
        warden = _warden(max_queries=1)
        async with Client(create_server(warden)) as client:
            await client.call_tool("run_query", {"sql": SQL})
            refused = await client.call_tool("run_query", {"sql": SQL})
            for _ in range(3):
                status = await client.call_tool("budget_status", {})
        assert refused.is_error
        assert refused.structured_content is not None
        assert refused.structured_content["code"] == "BUDGET_EXHAUSTED"
        assert status.is_error is False
        assert status.structured_content is not None
        assert status.structured_content["budget"]["exhausted"] == "max_queries"
        assert isinstance(warden.audit, MemoryAuditSink)
        assert len(warden.audit.events) == 2  # the two queries; asking isn't recorded

    async def test_the_instructions_explain_budgets(self, anyio_backend: str) -> None:
        async with Client(create_server(_warden())) as client:
            assert client.instructions is not None
            for word in ("budget_status", "BUDGET_EXHAUSTED", "COST_OVER_BUDGET"):
                assert word in client.instructions


POLICY = """\
version: 1
budgets:
  max_queries: 20
  max_refusals: 5
default_profile: public
profiles:
  public:
    tables: "*"
    budgets:
      max_queries: 3
      max_total_cost: 50000
  trusted:
    tables: "*"
    budgets:
      max_refusals: null
  admin:
    tables: "*"
"""


class TestConfig:
    def test_no_limit_is_set_unless_the_file_sets_one(self) -> None:
        config = parse_config("version: 1")
        assert not config.budgets.limited
        assert not select_profile(config).budget.limited

    def test_the_section_applies_to_the_implicit_profile(self) -> None:
        config = parse_config("version: 1\nbudgets:\n  max_queries: 20\n")
        assert select_profile(config).budget == BudgetConfig(max_queries=20)

    def test_a_profile_overrides_what_it_names_and_null_lifts_a_limit(self) -> None:
        config = parse_config(POLICY)
        assert select_profile(config, "public").budget == BudgetConfig(
            max_queries=3, max_total_cost=50_000, max_refusals=5
        )
        assert select_profile(config, "trusted").budget == BudgetConfig(max_queries=20)
        assert select_profile(config, "admin").budget == BudgetConfig(
            max_queries=20, max_refusals=5
        )

    @pytest.mark.parametrize(
        ("text", "problem"),
        [
            ("budgets:\n  max_queries: 0\n", "budgets.max_queries: Input should be greater than 0"),
            ("budgets:\n  max_query: 5\n", "budgets.max_query: Extra inputs are not permitted"),
            (
                "profiles:\n  p:\n    budgets:\n      max_rows: 5\n",
                "profiles.p.budgets.max_rows: Extra inputs are not permitted",
            ),
        ],
    )
    def test_bad_limits_are_errors(self, text: str, problem: str) -> None:
        with pytest.raises(ConfigError) as excinfo:
            parse_config("version: 1\n" + text)
        assert problem in str(excinfo.value)


class TestCli:
    def test_validate_shows_the_budgets(self, isolated_cli: Path) -> None:
        (isolated_cli / "warden.yaml").write_text(POLICY)
        lines = CliRunner().invoke(cli, ["config", "validate"]).output.splitlines()
        assert "  budgets:   per session: 20 queries, 5 refusals" in lines
        assert "               budget per session: 3 queries, cost 50,000, 5 refusals" in lines
        assert "               budget per session: 20 queries" in lines

    def test_a_profiles_budget_reaches_its_warden(
        self, isolated_cli: Path, engines: list[FakeEngine], audit_sinks: AuditSinks
    ) -> None:
        (isolated_cli / "warden.yaml").write_text(POLICY)
        outcome = CliRunner().invoke(cli, ["query", "select 1"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines()[-1] == (
            "session budget: 1 of 3 queries, 1 of 50,000 cost, 0 of 5 refusals used"
        )
        refused = CliRunner().invoke(cli, ["check", "delete from t", "--profile", "admin"])
        assert refused.exit_code == EXIT_REFUSED
        assert "  session budget: 0 of 20 queries, 1 of 5 refusals used" in (
            refused.output.splitlines()
        )
