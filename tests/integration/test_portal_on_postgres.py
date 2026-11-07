import json
from pathlib import Path
from typing import Any

import pytest

from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import build_warden
from sql_warden.config import EVERYTHING, load_config
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.profiles import Access
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse
from tests.portal.app import EXAMPLES, create_portal_app
from tests.portal.test_portal import PortalClient
from tests.support import serving

pytestmark = pytest.mark.integration


def test_the_portal_against_the_seeded_warehouse(warehouse: Warehouse) -> None:
    warden = Warden(PostgresEngine(warehouse.reader_dsn, max_rows=3), audit=MemoryAuditSink())
    with serving(create_portal_app(warden)) as base_url:
        client = PortalClient(base_url)
        client.connect()
        tables = client.call_tool("list_tables")["structuredContent"]["tables"]
        ran = client.call_tool("run_query", sql="select id, name from products order by id")
        refused = client.call_tool("run_query", sql="select pg_sleep(1)")

    assert [t["name"] for t in tables] == ["customers", "employee_salaries", "orders", "products"]
    rows = ran["structuredContent"]["result"]
    assert rows["rows"] == [[1, "Product 1"], [2, "Product 2"], [3, "Product 3"]]
    assert rows["truncated"] is True
    assert refused["structuredContent"]["code"] == "FUNCTION_NOT_ALLOWED"


def test_compare_public_and_admin_on_the_seeded_warehouse(warehouse: Warehouse) -> None:
    public = Access({("public", "products"): frozenset({"id", "name", "price_cents"})})
    wardens = {
        "public": Warden(
            PostgresEngine(warehouse.public_dsn),
            audit=MemoryAuditSink(),
            profile="public",
            access=public,
        ),
        "admin": Warden(
            PostgresEngine(warehouse.reader_dsn),
            audit=MemoryAuditSink(),
            profile="admin",
            access=Access(EVERYTHING),
        ),
    }
    sql = "select title, count(*) from employee_salaries group by title"
    outcomes = {}
    with serving(create_portal_app(wardens)) as base_url:
        for profile in wardens:
            client = PortalClient(base_url, endpoint=f"/p/{profile}/mcp")
            client.connect()
            outcomes[profile] = client.call_tool("run_query", sql=sql)["structuredContent"]
    assert outcomes["public"]["code"] == "TABLE_NOT_ALLOWED"
    assert outcomes["admin"]["result"]["row_count"] > 0


EXAMPLE_CONFIG = Path(__file__).parents[2] / "warden.example.yaml"


def _examples() -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = json.loads(EXAMPLES.read_text())["examples"]
    return examples


@pytest.mark.parametrize("example", _examples(), ids=lambda example: example["title"])
def test_every_docs_example_does_what_it_says(
    warehouse: Warehouse, tmp_path: Path, example: dict[str, Any]
) -> None:
    # The example config, pointed at the test warehouse, with a short timeout for the slow one.
    host_port = warehouse.reader_dsn.split("@")[1].split("/")[0]
    policy = tmp_path / "warden.yaml"
    policy.write_text(
        EXAMPLE_CONFIG.read_text()
        .replace("localhost:5433", host_port)
        .replace("statement_timeout_ms: 5000", "statement_timeout_ms: 500")
    )
    warden = build_warden(load_config(policy), example["profile"], audit=MemoryAuditSink())
    if example["expect"] == "failed":
        outcome = warden.run(example["sql"])
        assert outcome.decision.refused_by is None
        assert outcome.error is not None
        return
    decision = warden.check(example["sql"])
    refused = decision.refused_by
    code = refused.refusal.code if refused and refused.refusal else "allowed"
    assert code == example["expect"], refused and refused.refusal and refused.refusal.reason
