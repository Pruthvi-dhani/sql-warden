"""Session budgets against the seeded warehouse: real estimates, real rows, the example config."""

from pathlib import Path

import pytest

from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import build_warden
from sql_warden.config import BudgetConfig, load_config
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.models import Decision, RefusalCode
from sql_warden.sessions import Usage
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration

EXAMPLE_CONFIG = Path(__file__).parents[2] / "warden.example.yaml"
FULL_SCAN = "select sum(quantity) from orders"


def _code(decision: Decision) -> RefusalCode | None:
    refused = decision.refused_by
    return refused.refusal.code if refused and refused.refusal else None


def _warden(warehouse: Warehouse, **limits: float) -> Warden:
    return Warden(
        PostgresEngine(warehouse.reader_dsn, max_rows=100),
        audit=MemoryAuditSink(),
        budget=BudgetConfig.model_validate(limits),
    )


def _public(warehouse: Warehouse, tmp_path: Path) -> Warden:
    """The example config's public profile, pointed at the test warehouse."""
    host_port = warehouse.reader_dsn.split("@")[1].split("/")[0]
    policy = tmp_path / "warden.yaml"
    policy.write_text(EXAMPLE_CONFIG.read_text().replace("localhost:5433", host_port))
    return build_warden(load_config(policy), "public", audit=MemoryAuditSink())


def test_the_planners_estimates_add_up_until_the_next_doesnt_fit(warehouse: Warehouse) -> None:
    estimate = _warden(warehouse).check(FULL_SCAN).cost
    assert estimate is not None
    warden = _warden(warehouse, max_total_cost=estimate.total_cost * 2.5)
    assert warden.run(FULL_SCAN).result is not None
    assert warden.run(FULL_SCAN).result is not None
    third = warden.run(FULL_SCAN)
    assert third.result is None
    assert _code(third.decision) == RefusalCode.COST_OVER_BUDGET
    # What is left still buys something cheaper: an indexed lookup.
    cheap = warden.run("select id from orders where customer_id = 42 limit 5")
    assert cheap.result is not None
    status = warden.budget_status()
    assert status.usage.queries == 3
    assert status.usage.total_cost == pytest.approx(estimate.total_cost * 2, rel=0.01)
    assert status.usage.rows_returned == 2 + len(cheap.result.rows)


def test_public_in_the_example_config_runs_out_of_rows(
    warehouse: Warehouse, tmp_path: Path
) -> None:
    warden = _public(warehouse, tmp_path)
    assert warden.budget == BudgetConfig(
        max_queries=25, max_total_cost=50_000, max_rows_returned=500, max_refusals=10
    )
    for _ in range(10):  # 50 rows a query, public's row cap
        outcome = warden.run("select id, name from products")
        assert outcome.result is not None
        assert len(outcome.result.rows) == 50
    done = warden.run("select id, name from products")
    assert _code(done.decision) == RefusalCode.BUDGET_EXHAUSTED
    assert done.decision.refused_by is not None
    assert done.decision.refused_by.refusal is not None
    assert "it has been returned 500 rows" in done.decision.refused_by.refusal.reason
    assert [entry.check for entry in done.decision.trace] == ["budget"]
    assert done.decision.budget is not None
    assert done.decision.budget.exhausted == "max_rows_returned"


def test_public_is_locked_out_after_ten_refusals(warehouse: Warehouse, tmp_path: Path) -> None:
    warden = _public(warehouse, tmp_path)
    probes = [f"select * from {table}" for table in ("employee_salaries", "customers", "orders")]
    for attempt in range(10):
        decision = warden.check(probes[attempt % 3])
        assert _code(decision) == RefusalCode.TABLE_NOT_ALLOWED
    # From here on it isn't told even that: a table it may read is refused the same way.
    for sql in ("select * from employee_salaries", "select id from products"):
        decision = warden.check(sql)
        assert _code(decision) == RefusalCode.BUDGET_EXHAUSTED
        assert [entry.check for entry in decision.trace] == ["budget"]
    assert warden.run("select id from products").result is None
    assert warden.budget_status().usage == Usage(refusals=10)


def test_another_session_starts_with_its_whole_budget(warehouse: Warehouse, tmp_path: Path) -> None:
    warden = _public(warehouse, tmp_path)
    for _ in range(10):
        warden.check("select * from employee_salaries", session_id="probing")
    assert _code(warden.check("select id from products", session_id="probing")) == (
        RefusalCode.BUDGET_EXHAUSTED
    )
    assert warden.run("select id from products", session_id="another").result is not None
