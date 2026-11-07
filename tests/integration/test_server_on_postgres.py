import sys
from typing import Any

import psycopg
import pytest
from mcp import Client, StdioServerParameters

from sql_warden.audit import MemoryAuditSink
from sql_warden.engines import Column
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.server import create_server
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = [pytest.mark.integration, pytest.mark.anyio]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_tables_lists_what_the_reader_can_see(warehouse: Warehouse) -> None:
    tables = {t.name: t for t in PostgresEngine(warehouse.reader_dsn).tables()}
    assert set(tables) == {"customers", "employee_salaries", "orders", "products"}
    assert {t.schema for t in tables.values()} == {"public"}
    assert tables["customers"].columns[:3] == (
        Column("id", "integer"),
        Column("full_name", "text"),
        Column("email", "text"),
    )


async def test_run_query_returns_real_values_as_json(warehouse: Warehouse) -> None:
    server = create_server(
        Warden(PostgresEngine(warehouse.reader_dsn, max_rows=2), audit=MemoryAuditSink())
    )
    async with Client(server) as client:
        result = await client.call_tool(
            "run_query",
            {
                "sql": "select id, created_at, price_cents / 100.0 as price "
                "from customers cross join (select 637 as price_cents) p order by id"
            },
        )
    assert result.is_error is False
    assert result.structured_content is not None
    rows = result.structured_content["result"]
    assert rows["columns"] == ["id", "created_at", "price"]
    assert rows["truncated"] is True
    first = rows["rows"][0]
    assert first[0] == 1
    assert isinstance(first[1], str)
    assert first[1].startswith("20")  # an ISO 8601 timestamp
    assert first[2] == "6.3700000000000000"  # numeric stays exact


async def test_database_errors_reach_the_agent(warehouse: Warehouse) -> None:
    async with Client(
        create_server(Warden(PostgresEngine(warehouse.reader_dsn), audit=MemoryAuditSink()))
    ) as client:
        planned = await client.call_tool("run_query", {"sql": "select nope from products"})
        ran = await client.call_tool(
            "run_query", {"sql": "select 100 / (id - 1) from products order by id"}
        )
    # Caught while the cost check had it planned: refused, before anything ran.
    assert planned.is_error is True
    refused = _structured(planned)
    assert (refused["check"], refused["code"]) == ("cost", "PLAN_FAILED")
    assert refused["reason"].splitlines()[:3] == [
        'the database rejected the query while planning it: column "nope" does not exist',
        "  SELECT nope FROM products LIMIT 1001",  # the engine's default row cap
        "         ^",
    ]
    # Only found while running: the database's error.
    assert ran.is_error is True
    assert _structured(ran)["error"] == "division by zero"


async def test_the_cli_serves_over_stdio(audit_dsn: str) -> None:
    # No warehouse: listing tools works; a query can't have its cost estimated, so the dry run
    # and the real one are both refused, and both are recorded, under the name the client gave.
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "sql_warden", "serve", "--dsn", "postgresql://nobody:x@127.0.0.1:1/none"],
        env={"SQL_WARDEN_AUDIT_DSN": audit_dsn},
    )
    async with Client(params) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
        checked = await client.call_tool("check_query", {"sql": "select 1"})
        ran = await client.call_tool("run_query", {"sql": "select 1"})
    assert names == {"run_query", "check_query", "list_tables", "describe_table"}
    # A refused dry run is check_query's answer, not an error; a refused run_query is.
    assert (checked.is_error, ran.is_error) == (False, True)
    for result in (checked, ran):
        assert _structured(result)["code"] == "COST_UNAVAILABLE"
        assert "could not connect to the database" in _structured(result)["reason"]
    with psycopg.connect(audit_dsn) as conn:
        recorded = conn.execute(
            "SELECT dry_run, decision, client FROM audit_events WHERE id = ANY(%s) ORDER BY ts",
            ([_structured(checked)["audit_id"], _structured(ran)["audit_id"]],),
        ).fetchall()
    assert recorded == [(True, "refused", "mcp 0.1.0"), (False, "refused", "mcp 0.1.0")]


def _structured(result: Any) -> dict[str, Any]:
    assert result.structured_content is not None
    content: dict[str, Any] = result.structured_content
    return content
