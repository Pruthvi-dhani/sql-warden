import pytest

from sql_warden.config import EVERYTHING
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.profiles import Access
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse
from tests.portal.app import create_portal_app
from tests.portal.test_portal import PortalClient
from tests.support import serving

pytestmark = pytest.mark.integration


def test_the_portal_against_the_seeded_warehouse(warehouse: Warehouse) -> None:
    warden = Warden(PostgresEngine(warehouse.reader_dsn, max_rows=3))
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
        "public": Warden(PostgresEngine(warehouse.public_dsn), profile="public", access=public),
        "admin": Warden(
            PostgresEngine(warehouse.reader_dsn), profile="admin", access=Access(EVERYTHING)
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
