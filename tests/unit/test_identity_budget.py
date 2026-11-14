"""Budgets per caller: what one token's holder may use over a rolling window, whatever
session they use. A new connection is a new session, so without these a caller could start
a fresh session budget just by connecting again."""

import threading
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import cli
from sql_warden.config import (
    BudgetConfig,
    ConfigError,
    IdentityBudgetConfig,
    parse_config,
)
from sql_warden.engines import CostEstimate, Result
from sql_warden.models import Decision, RefusalCode
from sql_warden.pipeline.budget import window
from sql_warden.profiles import select_profile
from sql_warden.sessions import CallerCharge, Charge, MemorySessionStore, Usage
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine

SQL = "select id from products"
HOUR = 3600.0
TEN_ROWS = Result(
    columns=("id",), rows=tuple((n,) for n in range(10)), truncated=False, duration_ms=1
)


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def _warden(
    engine: FakeEngine | None = None,
    *,
    clock: Clock | None = None,
    session: dict[str, float] | None = None,
    **limits: float,
) -> Warden:
    return Warden(
        engine or FakeEngine(),
        audit=MemoryAuditSink(),
        budget=BudgetConfig.model_validate(session or {}),
        identity_budget=IdentityBudgetConfig.model_validate(limits),
        sessions=MemorySessionStore(clock=clock or Clock()),
    )


def _refusal(decision: Decision) -> tuple[RefusalCode, str] | None:
    refused = decision.refused_by
    if refused is None:
        return None
    assert refused.refusal is not None
    return refused.refusal.code, refused.refusal.reason


class TestOverEveryOneOfTheirSessions:
    def test_a_new_session_doesnt_start_a_new_budget(self) -> None:
        warden = _warden(max_queries=2)
        assert warden.run(SQL, session_id="first", identity="bot").result is not None
        assert warden.run(SQL, session_id="second", identity="bot").result is not None
        refused = warden.run(SQL, session_id="third", identity="bot")
        assert refused.result is None
        assert _refusal(refused.decision) == (
            RefusalCode.BUDGET_EXHAUSTED,
            "bot's budget for any 24 hours is used up: they have run 2 of their 2 queries in "
            "the last 24 hours, over all their sessions. Nothing more runs for them until "
            "earlier use is older than that",
        )

    def test_another_caller_has_their_own(self) -> None:
        warden = _warden(max_queries=1)
        warden.run(SQL, session_id="a", identity="bot")
        assert warden.run(SQL, session_id="a2", identity="bot").result is None
        assert warden.run(SQL, session_id="b", identity="other-bot").result is not None

    def test_requests_without_a_caller_are_not_held_to_it(self) -> None:
        # stdio, the CLI, HTTP without auth: nobody to hold to it, so only the session's.
        warden = _warden(max_queries=1)
        for _ in range(3):
            assert warden.run(SQL).result is not None

    def test_it_is_refused_by_the_gate_before_any_other_check(self) -> None:
        warden = _warden(max_queries=1)
        warden.run(SQL, session_id="a", identity="bot")
        decision = warden.check("not even sql", session_id="b", identity="bot")
        assert [entry.check for entry in decision.trace] == ["budget"]


class TestWhicheverRunsOutFirst:
    def test_the_session_first(self) -> None:
        warden = _warden(session={"max_queries": 1}, max_queries=5)
        warden.run(SQL, session_id="a", identity="bot")
        refused = _refusal(warden.run(SQL, session_id="a", identity="bot").decision)
        assert refused is not None
        assert refused[1].startswith("this session's budget is used up: it has run 1 of its 1")
        # The caller still has room, in another session.
        assert warden.run(SQL, session_id="b", identity="bot").result is not None

    def test_the_caller_first(self) -> None:
        warden = _warden(session={"max_queries": 5}, max_queries=1)
        warden.run(SQL, session_id="a", identity="bot")
        refused = _refusal(warden.run(SQL, session_id="a", identity="bot").decision)
        assert refused is not None
        assert refused[1].startswith("bot's budget for any 24 hours is used up")

    def test_a_charge_that_doesnt_fit_the_caller_isnt_charged_to_the_session(self) -> None:
        warden = _warden(session={"max_queries": 5}, max_queries=1)
        warden.run(SQL, session_id="a", identity="bot")
        warden.run(SQL, session_id="a", identity="bot")  # refused by the caller's budget
        assert warden.sessions.usage("a").queries == 1


class TestEachLimit:
    def test_cost(self) -> None:
        costly = FakeEngine(estimate=CostEstimate(40, est_rows=1, top_node="Seq Scan"))
        warden = _warden(costly, max_total_cost=100)
        warden.run(SQL, session_id="a", identity="bot")
        warden.run(SQL, session_id="b", identity="bot")
        refused = _refusal(warden.run(SQL, session_id="c", identity="bot").decision)
        assert refused == (
            RefusalCode.COST_OVER_BUDGET,
            "the planner estimates this query at 40, more than the 20 bot has left of the "
            "100 they may spend in any 24 hours. A cheaper query may still fit",
        )

    def test_rows(self) -> None:
        warden = _warden(FakeEngine(result=TEN_ROWS), max_rows_returned=15)
        warden.run(SQL, session_id="a", identity="bot")
        # This one still comes back: its rows are known only once it has run.
        assert warden.run(SQL, session_id="b", identity="bot").result is not None
        refused = _refusal(warden.run(SQL, session_id="c", identity="bot").decision)
        assert refused is not None
        assert "they have been returned 20 rows, and their limit is 15" in refused[1]

    def test_refusals_across_sessions(self) -> None:
        warden = _warden(max_refusals=2)
        for session in ("a", "b"):
            warden.check("select 1; select 2", session_id=session, identity="bot")
        refused = _refusal(warden.check(SQL, session_id="c", identity="bot"))
        assert refused is not None
        assert "2 of their requests were refused, and their limit is 2" in refused[1]

    def test_a_dry_run_says_whether_it_would_fit_and_is_charged_nothing(self) -> None:
        warden = _warden(max_queries=1)
        assert warden.check(SQL, session_id="a", identity="bot").allowed
        assert warden.check(SQL, session_id="a", identity="bot").allowed
        warden.run(SQL, session_id="a", identity="bot")
        decision = warden.check(SQL, session_id="b", identity="bot")
        assert _refusal(decision) is not None


class TestTheWindow:
    def test_use_older_than_the_window_stops_counting(self) -> None:
        clock = Clock()
        warden = _warden(clock=clock, max_queries=2, window_hours=1)
        warden.run(SQL, session_id="a", identity="bot")
        clock.now += 0.5 * HOUR
        warden.run(SQL, session_id="a", identity="bot")
        assert warden.run(SQL, session_id="a", identity="bot").result is None
        # The first is an hour old now: one more fits, and only one.
        clock.now += 0.5 * HOUR
        assert warden.run(SQL, session_id="a", identity="bot").result is not None
        assert warden.run(SQL, session_id="a", identity="bot").result is None

    @pytest.mark.parametrize(
        ("hours", "named"),
        [(24, "24 hours"), (1, "1 hour"), (0.5, "30 minutes"), (168, "7 days"), (36, "36 hours")],
    )
    def test_it_is_named_as_people_say_it(self, hours: float, named: str) -> None:
        assert window(hours) == named


class TestBudgetStatus:
    def test_it_shows_the_callers_budget_beside_the_sessions(self) -> None:
        warden = _warden(session={"max_queries": 5}, max_queries=3, window_hours=12)
        warden.run(SQL, session_id="a", identity="bot")
        warden.run(SQL, session_id="b", identity="bot")
        status = warden.budget_status("b", "bot")
        assert status.usage.queries == 1
        assert status.caller is not None
        assert (status.caller.name, status.caller.window_hours, status.caller.usage.queries) == (
            "bot",
            12,
            2,
        )
        assert status.caller.exhausted is None
        decision = warden.run(SQL, session_id="c", identity="bot").decision
        assert decision.budget is not None
        assert decision.budget.caller is not None
        assert decision.budget.caller.exhausted == "max_queries"

    def test_without_a_caller_there_is_none(self) -> None:
        assert _warden(max_queries=3).budget_status("a").caller is None


class TestMemoryStore:
    def test_a_charge_beyond_the_callers_limit_is_not_made(self) -> None:
        store = MemorySessionStore(clock=Clock())
        bot = CallerCharge("bot", HOUR, within=BudgetConfig(max_queries=1))
        assert store.charge("a", Usage(queries=1), caller=bot).made
        refused = store.charge("b", Usage(queries=1), caller=bot)
        assert refused == Charge(Usage(), "max_queries", "caller", Usage(queries=1))
        assert store.usage("b") == Usage()

    def test_charges_without_limits_are_counted(self) -> None:
        store = MemorySessionStore(clock=Clock())
        store.charge("a", Usage(refusals=1), caller=CallerCharge("bot", HOUR))
        assert store.caller_usage("bot", HOUR) == Usage(refusals=1)

    def test_callers_charging_at_once_never_go_over(self) -> None:
        store = MemorySessionStore()
        bot = CallerCharge("bot", HOUR, within=BudgetConfig(max_queries=50))
        made: list[bool] = []

        def spend(session: str) -> None:
            for _ in range(20):
                made.append(store.charge(session, Usage(queries=1), caller=bot).made)

        threads = [threading.Thread(target=spend, args=(f"s{n}",)) for n in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert (made.count(True), store.caller_usage("bot", HOUR).queries) == (50, 50)


def _config(text: str) -> Any:
    auth = "auth:\n  api_keys:\n    - {name: bot, profile: support, sha256: " + "a" * 64 + "}\n"
    return parse_config("version: 1\nprofiles:\n  support:\n    tables: {}\n" + auth + text)


class TestConfig:
    def test_top_level_and_per_profile(self) -> None:
        config = _config(
            "identity_budgets:\n  window_hours: 12\n  max_queries: 100\n  max_refusals: 20\n"
        )
        budget = select_profile(config, "support").identity_budget
        assert (budget.window_hours, budget.max_queries, budget.max_refusals) == (12, 100, 20)
        config = _config(
            "identity_budgets:\n  max_queries: 100\n  max_refusals: 20\n"
            "profiles:\n  support:\n    tables: {}\n"
            "    identity_budgets: {max_queries: 10, max_refusals: null}\n"
        )
        budget = select_profile(config, "support").identity_budget
        assert (budget.window_hours, budget.max_queries, budget.max_refusals) == (24, 10, None)

    def test_none_unless_set(self) -> None:
        assert not select_profile(_config(""), "support").identity_budget.limited

    def test_a_window_alone_is_no_limit(self) -> None:
        assert not IdentityBudgetConfig(window_hours=1).limited

    @pytest.mark.parametrize("hours", ["0", "-1", "745"])
    def test_a_window_out_of_range(self, hours: str) -> None:
        with pytest.raises(ConfigError, match="window_hours"):
            _config(f"identity_budgets:\n  window_hours: {hours}\n  max_queries: 1\n")

    @pytest.mark.parametrize(
        ("text", "where"),
        [
            ("identity_budgets:\n  max_queries: 1\n", "identity_budgets"),
            (
                "profiles:\n  p:\n    tables: {}\n    identity_budgets: {max_queries: 1}\n",
                "profiles.p.identity_budgets",
            ),
        ],
    )
    def test_without_auth_it_would_never_be_enforced(self, text: str, where: str) -> None:
        with pytest.raises(ConfigError) as excinfo:
            parse_config("version: 1\n" + text)
        assert (
            f"{where} limits what each caller with a token may use, but there is no auth "
            "section, so no caller has one: it would never be enforced"
        ) in str(excinfo.value)


def test_validate_shows_them(tmp_path: Path) -> None:
    path = tmp_path / "warden.yaml"
    path.write_text(
        "version: 1\nidentity_budgets:\n  window_hours: 12\n  max_queries: 100\n"
        "profiles:\n  support:\n    tables: {}\n    identity_budgets: {max_queries: 10}\n"
        "auth:\n  api_keys:\n    - {name: bot, profile: support, sha256: " + "a" * 64 + "}\n"
    )
    lines = CliRunner().invoke(cli, ["config", "validate", str(path)]).output.splitlines()
    assert "             per caller over any 12 hours: 100 queries" in lines
    assert "               budget per caller over any 12 hours: 10 queries" in lines
