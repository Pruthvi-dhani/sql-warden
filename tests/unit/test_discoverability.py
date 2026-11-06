"""What a profile can see of the catalog: only what it may query, nothing else exists."""

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from mcp import Client
from mcp_types import TextContent

from sql_warden.cli import EXIT_ERROR, cli
from sql_warden.config import EVERYTHING
from sql_warden.profiles import Access
from sql_warden.server import create_server
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine
from tests.unit.test_access_check import ADMIN, CATALOG, PUBLIC


def _warden(access: Access | None, profile: str = "public") -> Warden:
    return Warden(FakeEngine(catalog=CATALOG), profile=profile, access=access)


def _seen(warden: Warden) -> dict[str, list[str]]:
    return {f"{t.schema}.{t.name}": [c.name for c in t.columns] for t in warden.tables()}


class TestTables:
    def test_a_profile_sees_only_what_it_may_query(self) -> None:
        assert _seen(_warden(PUBLIC)) == {
            "public.products": ["id", "name", "price_cents"],  # catalog order, not rule order
            "public.orders": ["id", "product_id", "quantity"],
            "reports.daily": ["day", "total"],
        }

    def test_every_table_and_no_rules_see_the_whole_catalog(self) -> None:
        everything = {f"{t.schema}.{t.name}": [c.name for c in t.columns] for t in CATALOG}
        assert _seen(_warden(ADMIN, "admin")) == everything
        assert _seen(_warden(None, "all")) == everything

    def test_a_profile_without_tables_sees_nothing(self) -> None:
        assert _warden(Access({})).tables() == ()

    def test_a_rule_for_a_missing_table_shows_nothing(self) -> None:
        access = Access({("public", "gone"): EVERYTHING})
        assert _warden(access).tables() == ()

    def test_all_columns_says_whether_star_works(self) -> None:
        warden = _warden(PUBLIC)
        assert {t.name: warden.all_columns(t) for t in warden.tables()} == {
            "products": False,
            "orders": False,
            "daily": True,
        }


class TestTable:
    @pytest.mark.parametrize("name", ["products", "public.products", "PRODUCTS", "Public.Products"])
    def test_names_are_read_as_in_sql(self, name: str) -> None:
        table = _warden(PUBLIC).table(name)
        assert table is not None
        assert (table.schema, table.name) == ("public", "products")
        assert [c.name for c in table.columns] == ["id", "name", "price_cents"]

    @pytest.mark.parametrize(
        "name",
        [
            '"Products"',  # quoted: keeps its case, and there's no Products
            "employee_salaries",  # exists, but not for this profile
            "nosuch",
            "customers",
            "warehouse.public.products",
            "not a table!",
            "",
        ],
    )
    def test_anything_else_is_not_there(self, name: str) -> None:
        assert _warden(PUBLIC).table(name) is None

    def test_quoted_names_keep_their_case(self) -> None:
        warden = _warden(ADMIN, "admin")
        assert warden.table('"MixedCase"') is not None
        assert warden.table("MixedCase") is None  # folds to mixedcase


def _structured(result: Any) -> dict[str, Any]:
    assert result.structured_content is not None
    content: dict[str, Any] = result.structured_content
    return content


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
class TestMcp:
    async def test_list_tables(self, anyio_backend: str) -> None:
        async with Client(create_server(_warden(PUBLIC))) as client:
            payload = _structured(await client.call_tool("list_tables", {}))
        assert payload["profile"] == "public"
        assert [(t["schema"], t["name"], t["all_columns"]) for t in payload["tables"]] == [
            ("public", "products", False),
            ("public", "orders", False),
            ("reports", "daily", True),
        ]

    async def test_describe_table(self, anyio_backend: str) -> None:
        async with Client(create_server(_warden(PUBLIC))) as client:
            result = await client.call_tool("describe_table", {"table": "products"})
        assert result.is_error is False
        assert _structured(result) == {
            "profile": "public",
            "table": {
                "schema": "public",
                "name": "products",
                "columns": [
                    {"name": "id", "type": "integer"},
                    {"name": "name", "type": "integer"},
                    {"name": "price_cents", "type": "integer"},
                ],
                "all_columns": False,
            },
        }

    @pytest.mark.parametrize("table", ["employee_salaries", "nosuch"])
    async def test_forbidden_and_missing_tables_look_the_same(
        self, anyio_backend: str, table: str
    ) -> None:
        async with Client(create_server(_warden(PUBLIC))) as client:
            result = await client.call_tool("describe_table", {"table": table})
        assert result.is_error is True
        (content,) = result.content
        assert isinstance(content, TextContent)
        assert content.text.endswith(f": table {table} is not available to profile public")

    async def test_the_instructions_mention_it(self, anyio_backend: str) -> None:
        async with Client(create_server(_warden(PUBLIC))) as client:
            assert client.instructions is not None
            assert "describe_table" in client.instructions
            assert "all_columns: true" in client.instructions


@pytest.fixture
def policy(isolated_cli: Path) -> Path:
    path = isolated_cli / "warden.yaml"
    path.write_text(
        "version: 1\ndefault_profile: public\nprofiles:\n"
        "  public:\n    tables:\n      public.products: [id]\n"
        '  admin:\n    tables: "*"\n'
    )
    return path


class TestCli:
    def test_list(self, engines: list[FakeEngine], policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["tables"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines() == [
            "public.products  id  (some columns)",
            "(1 table, profile public)",
        ]

    def test_list_for_another_profile(self, engines: list[FakeEngine], policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["tables", "--profile", "admin"])
        assert outcome.output.splitlines() == [
            "public.products  id, name",
            "(1 table, profile admin)",
        ]

    def test_describe(self, engines: list[FakeEngine], policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["tables", "products"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines() == [
            "public.products (profile public)",
            "  id  integer",
            "SELECT * is not allowed: the profile may read only these columns, so name them",
        ]

    def test_describe_something_unavailable(self, engines: list[FakeEngine], policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["tables", "employee_salaries"])
        assert outcome.exit_code == EXIT_ERROR
        assert (
            outcome.output == "Error: table employee_salaries is not available to profile public\n"
        )

    def test_json_is_what_the_tools_return(self, engines: list[FakeEngine], policy: Path) -> None:
        listed = json.loads(CliRunner().invoke(cli, ["tables", "--json"]).output)
        assert listed == {
            "profile": "public",
            "tables": [
                {
                    "schema": "public",
                    "name": "products",
                    "columns": [{"name": "id", "type": "integer"}],
                    "all_columns": False,
                }
            ],
        }
        one = json.loads(CliRunner().invoke(cli, ["tables", "products", "--json"]).output)
        assert one == {"profile": "public", "table": listed["tables"][0]}

    def test_without_profiles(self, engines: list[FakeEngine]) -> None:
        outcome = CliRunner().invoke(cli, ["tables"])
        assert outcome.output.splitlines() == [
            "public.products  id, name",
            "(1 table, profile all)",
        ]
