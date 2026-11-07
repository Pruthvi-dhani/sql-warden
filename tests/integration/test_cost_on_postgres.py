"""The cost check against the seeded warehouse: the planner's real estimates, real limits."""

import time
from pathlib import Path

import pytest

from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import build_warden
from sql_warden.config import CostConfig, load_config
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.models import RefusalCode
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration

EXAMPLE_CONFIG = Path(__file__).parents[2] / "warden.example.yaml"


def _warden(warehouse: Warehouse, limit: float = 1_000_000) -> Warden:
    return Warden(
        PostgresEngine(warehouse.reader_dsn, max_rows=100),
        audit=MemoryAuditSink(),
        cost=CostConfig(max_total_cost=limit),
    )


def test_the_cartesian_join_is_refused_before_it_runs(warehouse: Warehouse) -> None:
    started = time.perf_counter()
    outcome = _warden(warehouse).run("select count(*) from orders a cross join orders b")
    assert time.perf_counter() - started < 2  # planned, never run: it would take hours
    refused = outcome.decision.refused_by
    assert refused is not None
    assert refused.refusal is not None
    assert (refused.check, refused.refusal.code) == ("cost", RefusalCode.COST_TOO_HIGH)
    assert "over profile all's limit of 1,000,000; most of it is Nested Loop" in (
        refused.refusal.reason
    )
    assert outcome.decision.cost is not None
    assert outcome.decision.cost.total_cost > 1e9
    assert outcome.result is None


def test_the_filtered_query_passes_and_runs(warehouse: Warehouse) -> None:
    outcome = _warden(warehouse).run(
        "select o.id, o.quantity from orders o where o.customer_id = 42 order by o.id"
    )
    assert outcome.decision.allowed, outcome.decision.refused_by
    assert outcome.decision.cost is not None
    assert outcome.decision.cost.total_cost < 1000  # the index on customer_id
    assert outcome.result is not None
    assert len(outcome.result.rows) > 0


def test_a_full_scan_fits_the_default_limit_but_not_a_tight_one(warehouse: Warehouse) -> None:
    sql = "select sum(quantity) from orders"
    assert _warden(warehouse).check(sql).allowed
    refused = _warden(warehouse, limit=1000).check(sql).refused_by
    assert refused is not None
    assert refused.refusal is not None
    assert refused.refusal.code == RefusalCode.COST_TOO_HIGH
    assert "Seq Scan on orders" in refused.refusal.reason


def test_each_profile_in_the_example_config_has_its_own_limit(
    warehouse: Warehouse, tmp_path: Path
) -> None:
    host_port = warehouse.reader_dsn.split("@")[1].split("/")[0]
    policy = tmp_path / "warden.yaml"
    policy.write_text(EXAMPLE_CONFIG.read_text().replace("localhost:5433", host_port))
    config = load_config(policy)
    sql = "select count(*) from products a, products b, products c"  # 8M rows to count
    public = build_warden(config, "public", audit=MemoryAuditSink()).check(sql)
    admin = build_warden(config, "admin", audit=MemoryAuditSink()).check(sql)
    assert public.refused_by is not None
    assert public.refused_by.refusal is not None
    assert public.refused_by.refusal.code == RefusalCode.COST_TOO_HIGH
    assert "over profile public's limit of 10,000" in public.refused_by.refusal.reason
    assert admin.allowed, admin.refused_by
    assert public.cost is not None
    assert admin.cost is not None
    assert public.cost.total_cost == admin.cost.total_cost  # one query, one estimate
    assert (public.cost_limit, admin.cost_limit) == (10_000, 1_000_000)


def test_each_profile_in_the_example_config_has_its_own_row_cap(
    warehouse: Warehouse, tmp_path: Path
) -> None:
    host_port = warehouse.reader_dsn.split("@")[1].split("/")[0]
    policy = tmp_path / "warden.yaml"
    policy.write_text(EXAMPLE_CONFIG.read_text().replace("localhost:5433", host_port))
    config = load_config(policy)
    public = build_warden(config, "public", audit=MemoryAuditSink()).run("select id from products")
    admin = build_warden(config, "admin", audit=MemoryAuditSink()).run("select id from orders")
    assert public.decision.sql == "SELECT id FROM public.products LIMIT 51"
    assert admin.decision.sql == "SELECT id FROM public.orders LIMIT 1001"
    assert public.result is not None
    assert admin.result is not None
    assert (len(public.result.rows), public.result.truncated) == (50, True)
    assert (len(admin.result.rows), admin.result.truncated) == (1000, True)
