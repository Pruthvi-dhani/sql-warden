"""The session store: each session's usage, charged atomically, and session ids."""

import threading
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from sql_warden.config import BudgetConfig, ConfigError, parse_config
from sql_warden.sessions import (
    Charge,
    MemorySessionStore,
    SessionStore,
    Usage,
    new_session_id,
    over,
    valid_session_id,
)


def _together(threads: int, work: Callable[[], None]) -> None:
    """Run work on that many threads at once, released together."""
    start = threading.Barrier(threads)

    def run() -> None:
        start.wait()
        work()

    running = [threading.Thread(target=run) for _ in range(threads)]
    for thread in running:
        thread.start()
    for thread in running:
        thread.join()


class TestSessionIds:
    def test_new_ids_are_valid_and_differ(self) -> None:
        ids = {new_session_id() for _ in range(100)}
        assert len(ids) == 100
        assert all(valid_session_id(session_id) for session_id in ids)

    @pytest.mark.parametrize("name", ["nightly-report", "a", "run_42", "team:etl.2026", "9" * 64])
    def test_names_that_can_be_a_session(self, name: str) -> None:
        assert valid_session_id(name)

    @pytest.mark.parametrize(
        "name", ["", " ", "has space", "-leading", "a\nb", "x" * 65, "semi;colon", "né"]
    )
    def test_names_that_cant(self, name: str) -> None:
        assert not valid_session_id(name)


class TestUsage:
    def test_starts_at_nothing(self) -> None:
        assert Usage() == Usage(queries=0, total_cost=0.0, rows_returned=0, refusals=0)

    def test_adds_up_part_by_part(self) -> None:
        total = Usage(queries=1, total_cost=10.5, rows_returned=3) + Usage(
            queries=2, total_cost=0.5, refusals=4
        )
        assert total == Usage(queries=3, total_cost=11.0, rows_returned=3, refusals=4)


class TestOver:
    BUDGET = BudgetConfig(max_queries=3, max_total_cost=100, max_rows_returned=50, max_refusals=2)

    def test_within_every_limit(self) -> None:
        assert (
            over(Usage(queries=2, total_cost=99.9, rows_returned=49, refusals=1), self.BUDGET)
            is None
        )

    def test_equal_to_a_limit_is_within_it(self) -> None:
        assert (
            over(Usage(queries=3, total_cost=100, rows_returned=50, refusals=2), self.BUDGET)
            is None
        )

    @pytest.mark.parametrize(
        ("usage", "limit"),
        [
            (Usage(queries=4), "max_queries"),
            (Usage(total_cost=100.01), "max_total_cost"),
            (Usage(rows_returned=51), "max_rows_returned"),
            (Usage(refusals=3), "max_refusals"),
            (Usage(queries=9, refusals=9), "max_queries"),  # the first one over
        ],
    )
    def test_names_the_limit(self, usage: Usage, limit: str) -> None:
        assert over(usage, self.BUDGET) == limit

    def test_a_limit_left_out_is_not_enforced(self) -> None:
        assert over(Usage(queries=10**9, total_cost=1e30), BudgetConfig(max_refusals=5)) is None


class TestMemorySessionStore:
    def test_it_is_a_session_store(self) -> None:
        store: SessionStore = MemorySessionStore()
        assert store.usage("s") == Usage()

    def test_a_session_never_charged_has_used_nothing_and_isnt_kept(self) -> None:
        store = MemorySessionStore()
        assert store.usage("unseen") == Usage()
        assert len(store) == 0

    def test_charges_add_up(self) -> None:
        store = MemorySessionStore()
        store.charge("s", Usage(queries=1, total_cost=20.0))
        charge = store.charge("s", Usage(queries=1, total_cost=5.5, rows_returned=7))
        assert charge == Charge(Usage(queries=2, total_cost=25.5, rows_returned=7))
        assert charge.made
        assert store.usage("s") == charge.usage

    def test_sessions_are_separate(self) -> None:
        store = MemorySessionStore()
        store.charge("a", Usage(queries=3))
        store.charge("b", Usage(refusals=1))
        assert (store.usage("a"), store.usage("b")) == (Usage(queries=3), Usage(refusals=1))

    def test_usage_only_grows(self) -> None:
        store = MemorySessionStore()
        with pytest.raises(ValueError, match="can't be negative"):
            store.charge("s", Usage(queries=-1))
        assert store.usage("s") == Usage()


class TestChargingWithinABudget:
    BUDGET = BudgetConfig(max_queries=2, max_total_cost=100)

    def test_a_charge_that_fits_is_made(self) -> None:
        store = MemorySessionStore()
        charge = store.charge("s", Usage(queries=1, total_cost=100), within=self.BUDGET)
        assert charge == Charge(Usage(queries=1, total_cost=100))

    def test_the_last_one_fits_and_the_next_does_not(self) -> None:
        store = MemorySessionStore()
        store.charge("s", Usage(queries=1), within=self.BUDGET)
        assert store.charge("s", Usage(queries=1), within=self.BUDGET).made
        refused = store.charge("s", Usage(queries=1), within=self.BUDGET)
        assert refused == Charge(Usage(queries=2), exceeded="max_queries")
        assert not refused.made

    def test_a_charge_over_one_limit_charges_nothing(self) -> None:
        store = MemorySessionStore()
        store.charge("s", Usage(queries=1, total_cost=60), within=self.BUDGET)
        refused = store.charge("s", Usage(queries=1, total_cost=41), within=self.BUDGET)
        assert refused.exceeded == "max_total_cost"
        # All or nothing: the query that didn't fit its cost isn't counted as a query either.
        assert store.usage("s") == Usage(queries=1, total_cost=60)

    def test_a_refused_charge_doesnt_start_a_session(self) -> None:
        store = MemorySessionStore()
        assert not store.charge("s", Usage(total_cost=101), within=self.BUDGET).made
        assert len(store) == 0

    def test_a_session_already_over_stays_refused(self) -> None:
        # Rows are only known once a query has run, so they are charged without a budget and
        # can pass their limit; from then on, nothing fits.
        budget = BudgetConfig(max_rows_returned=10)
        store = MemorySessionStore()
        store.charge("s", Usage(rows_returned=25))
        assert store.charge("s", Usage(queries=1), within=budget).exceeded == "max_rows_returned"

    def test_without_a_budget_nothing_is_refused(self) -> None:
        store = MemorySessionStore()
        assert store.charge("s", Usage(queries=10**6, total_cost=1e12)).made


class TestConcurrency:
    def test_no_charge_is_lost(self) -> None:
        store = MemorySessionStore()
        spent = Usage(queries=1, total_cost=2.0, rows_returned=3, refusals=1)

        def work() -> None:
            for _ in range(500):
                store.charge("s", spent)

        _together(16, work)
        assert store.usage("s") == Usage(
            queries=8000, total_cost=16000.0, rows_returned=24000, refusals=8000
        )

    def test_a_limit_is_never_passed(self) -> None:
        store = MemorySessionStore()
        budget = BudgetConfig(max_queries=100)
        made = []

        def work() -> None:
            for _ in range(50):
                if store.charge("s", Usage(queries=1), within=budget).made:
                    made.append(1)

        _together(16, work)  # 800 tries at a budget of 100
        assert len(made) == 100
        assert store.usage("s") == Usage(queries=100)

    def test_sessions_charged_at_once_stay_separate(self) -> None:
        store = MemorySessionStore()
        names = iter([f"s{n}" for n in range(8)])
        lock = threading.Lock()

        def work() -> None:
            with lock:
                name = next(names)
            for _ in range(300):
                store.charge(name, Usage(queries=1))

        _together(8, work)
        assert [store.usage(f"s{n}") for n in range(8)] == [Usage(queries=300)] * 8


class TestForgetting:
    def test_the_session_charged_longest_ago_is_forgotten(self) -> None:
        store = MemorySessionStore(max_sessions=2)
        store.charge("a", Usage(queries=1))
        store.charge("b", Usage(queries=1))
        store.charge("a", Usage(queries=1))  # a is now the more recent
        store.charge("c", Usage(queries=1))
        assert len(store) == 2
        assert store.usage("b") == Usage()
        assert (store.usage("a"), store.usage("c")) == (Usage(queries=2), Usage(queries=1))

    def test_it_needs_room_for_one(self) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            MemorySessionStore(max_sessions=0)


class TestBudgetConfig:
    def test_no_limit_is_set_by_default(self) -> None:
        assert BudgetConfig().model_dump() == {
            "max_queries": None,
            "max_total_cost": None,
            "max_rows_returned": None,
            "max_refusals": None,
        }

    @pytest.mark.parametrize(
        "limits",
        [{"max_queries": 0}, {"max_total_cost": -1}, {"max_refusals": 1.5}, {"max_query": 3}],
    )
    def test_limits_must_be_positive_and_known(self, limits: dict[str, float]) -> None:
        with pytest.raises(ValidationError):
            BudgetConfig.model_validate(limits)

    def test_warden_yaml_doesnt_take_budgets_before_the_check_that_enforces_them(self) -> None:
        # A rule in the file is never silently ignored: the section arrives with its check.
        with pytest.raises(ConfigError, match="budgets: Extra inputs are not permitted"):
            parse_config("version: 1\nbudgets:\n  max_queries: 10\n")
