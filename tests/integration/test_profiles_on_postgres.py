"""Profiles against the seeded warehouse: the `public` role is limited by Postgres itself."""

from pathlib import Path

import pytest
from click.testing import CliRunner
from mcp import Client

from sql_warden.catalog import Catalog
from sql_warden.cli import EXIT_ERROR, EXIT_REFUSED, build_warden, cli
from sql_warden.config import load_config
from sql_warden.engines import QueryFailed
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.server import create_server
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration


@pytest.fixture
def policy(warehouse: Warehouse, audit_dsn: str, tmp_path: Path) -> Path:
    path = tmp_path / "warden.yaml"
    path.write_text(
        f"version: 1\nwarehouse:\n  dsn: {warehouse.reader_dsn}\n"
        f"audit:\n  dsn: {audit_dsn}\n"
        f"default_profile: public\nprofiles:\n"
        f"  public:\n    dsn: {warehouse.public_dsn}\n"
        f"    tables:\n      public.products: [id, name, price_cents]\n"
        f'  admin:\n    tables: "*"\n'
        # Misconfigured on purpose: its rules allow everything, its role doesn't.
        f'  loose:\n    dsn: {warehouse.public_dsn}\n    tables: "*"\n'
    )
    return path


class TestPublicRole:
    def test_its_catalog_is_three_product_columns(self, warehouse: Warehouse) -> None:
        tables = Catalog(PostgresEngine(warehouse.public_dsn)).tables()
        assert [(t.name, [c.name for c in t.columns]) for t in tables] == [
            ("products", ["id", "name", "price_cents"])
        ]

    def test_it_reads_its_columns(self, warehouse: Warehouse) -> None:
        result = PostgresEngine(warehouse.public_dsn).execute(
            "SELECT id, name, price_cents FROM products ORDER BY id LIMIT 1"
        )
        assert result.rows == ((1, "Product 1", result.rows[0][2]),)

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT * FROM employee_salaries",
            "SELECT email FROM customers",
            "SELECT category FROM products",  # a column the role has no grant on
            "SELECT * FROM products",
        ],
    )
    def test_the_database_refuses_the_rest(self, warehouse: Warehouse, sql: str) -> None:
        with pytest.raises(QueryFailed) as caught:
            PostgresEngine(warehouse.public_dsn).execute(sql)
        assert caught.value.sqlstate == "42501"  # insufficient_privilege
        assert str(caught.value).startswith("permission denied for table")


class TestCli:
    def _query(self, policy: Path, *args: str) -> tuple[int, str]:
        outcome = CliRunner().invoke(cli, ["--config", str(policy), "query", *args])
        return outcome.exit_code, outcome.output

    def test_the_default_profile_cannot_read_salaries(self, policy: Path) -> None:
        code, output = self._query(policy, "select count(*) from employee_salaries")
        assert code == EXIT_REFUSED
        assert "TABLE_NOT_ALLOWED: table public.employee_salaries is not available" in output

    def test_every_table_means_every_table_its_role_can_read(self, policy: Path) -> None:
        # The catalog is read as the profile's role, so salaries don't exist for loose.
        code, output = self._query(
            policy, "select count(*) from employee_salaries", "--profile", "loose"
        )
        assert code == EXIT_REFUSED
        assert "table public.employee_salaries is not available to profile loose" in output

    def test_the_role_still_refuses_when_the_rules_are_too_wide(self, policy: Path) -> None:
        # Defence in depth: loose's rules allow * on products, its role has three columns.
        code, output = self._query(policy, "select * from products", "--profile", "loose")
        assert code == EXIT_ERROR
        assert "Error: permission denied for table products" in output

    def test_admin_can(self, policy: Path) -> None:
        code, output = self._query(
            policy, "select count(*) from employee_salaries", "--profile", "admin"
        )
        assert code == 0, output
        assert output.splitlines()[2] == "50"
        assert "profile admin)" in output.splitlines()[3]

    def test_dsn_flag_does_not_widen_the_public_profile(
        self, policy: Path, warehouse: Warehouse
    ) -> None:
        code, output = self._query(
            policy, "select * from products", "--profile", "loose", "--dsn", warehouse.admin_dsn
        )
        assert code == EXIT_ERROR
        assert "permission denied for table products" in output


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
@pytest.mark.parametrize(
    ("profile", "tables"),
    [
        ("public", {"products"}),
        ("admin", {"customers", "employee_salaries", "orders", "products"}),
    ],
)
async def test_each_profile_lists_what_its_role_can_read(
    policy: Path, anyio_backend: str, profile: str, tables: set[str]
) -> None:
    warden = build_warden(load_config(policy), profile)
    async with Client(create_server(warden)) as client:
        result = await client.call_tool("list_tables", {})
    assert result.structured_content is not None
    assert result.structured_content["profile"] == profile
    assert {t["name"] for t in result.structured_content["tables"]} == tables
