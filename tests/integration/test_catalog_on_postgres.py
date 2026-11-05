from collections.abc import Iterator

import psycopg
import pytest
import sqlglot
from sqlglot import exp
from sqlglot.optimizer.qualify import qualify

from sql_warden.catalog import Catalog
from sql_warden.engines.postgres import PostgresEngine
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration


@pytest.fixture
def odd_names(warehouse: Warehouse) -> Iterator[None]:
    """A schema with a mixed-case table and types sqlglot reads differently, dropped after."""
    with psycopg.connect(warehouse.admin_dsn, autocommit=True) as conn:
        conn.execute("CREATE SCHEMA catalog_test")
        conn.execute("CREATE TYPE catalog_test.mood AS ENUM ('ok', 'meh')")
        conn.execute(
            'CREATE TABLE catalog_test."MixedCase" '
            '("Id" integer, tags text[], doc tsvector, mood catalog_test.mood, lower_name text)'
        )
    try:
        yield
    finally:
        with psycopg.connect(warehouse.admin_dsn, autocommit=True) as conn:
            conn.execute("DROP SCHEMA catalog_test CASCADE")


def test_the_reader_sees_the_demo_tables(warehouse: Warehouse) -> None:
    catalog = Catalog(PostgresEngine(warehouse.reader_dsn))
    schema = catalog.schema()
    assert schema.column_names("public.customers") == [
        "id",
        "full_name",
        "email",
        "phone",
        "ssn",
        "country",
        "created_at",
    ]
    assert schema.get_column_type("public.customers", "created_at").sql() == "TIMESTAMPTZ"
    assert schema.get_column_type("public.orders", "quantity").sql() == "INT"
    assert {t.name for t in catalog.tables()} == {
        "customers",
        "employee_salaries",
        "orders",
        "products",
    }


def test_star_expands_to_the_real_columns(warehouse: Warehouse) -> None:
    catalog = Catalog(PostgresEngine(warehouse.reader_dsn))
    tree = qualify(
        sqlglot.parse_one("select * from products p", dialect="postgres"),
        schema=catalog.schema(),
        dialect="postgres",
        db="public",
    )
    assert isinstance(tree, exp.Select)
    assert [select.alias for select in tree.selects] == ["id", "name", "category", "price_cents"]


def test_tables_the_role_cannot_read_are_not_in_its_catalog(
    warehouse: Warehouse, odd_names: None
) -> None:
    # The reader has no grant on catalog_test; the admin who created it does.
    assert Catalog(PostgresEngine(warehouse.reader_dsn)).table("catalog_test", "MixedCase") is None
    assert Catalog(PostgresEngine(warehouse.admin_dsn)).table("catalog_test", "MixedCase")


def test_mixed_case_names_and_odd_types(warehouse: Warehouse, odd_names: None) -> None:
    catalog = Catalog(PostgresEngine(warehouse.admin_dsn))
    schema = catalog.schema()
    table = 'catalog_test."MixedCase"'
    assert schema.column_names(table) == ["Id", "tags", "doc", "mood", "lower_name"]
    assert [schema.get_column_type(table, c).sql() for c in ("tags", "doc")] == [
        "ARRAY",
        "UNKNOWN",
    ]
    tree = qualify(
        sqlglot.parse_one('select "Id", LOWER_NAME from catalog_test."MixedCase"'),
        schema=schema,
        dialect="postgres",
        validate_qualify_columns=True,
    )
    assert isinstance(tree, exp.Select)
    assert [select.alias for select in tree.selects] == ["Id", "lower_name"]
