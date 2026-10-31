import psycopg
import pytest
from psycopg import errors

from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration


def _scalar(dsn: str, sql: str) -> object:
    with psycopg.connect(dsn) as conn:
        row = conn.execute(sql).fetchone()
        assert row is not None
        return row[0]


@pytest.mark.parametrize(
    ("table", "expected"),
    [
        ("products", 200),
        ("customers", 10_000),
        ("orders", 1_000_000),
        ("employee_salaries", 50),
    ],
)
def test_seed_row_counts(warehouse: Warehouse, table: str, expected: int) -> None:
    assert _scalar(warehouse.admin_dsn, f"SELECT count(*) FROM {table}") == expected


def test_seed_is_deterministic(warehouse: Warehouse) -> None:
    with psycopg.connect(warehouse.admin_dsn) as conn:
        row = conn.execute(
            "SELECT full_name, email, phone, ssn, country FROM customers WHERE id = 1"
        ).fetchone()
    assert row == ("Grace Lovelace", "customer1@example.com", "+1-555-7919", "729-63-2843", "GB")


def test_order_totals_match_product_prices(warehouse: Warehouse) -> None:
    mismatches = _scalar(
        warehouse.admin_dsn,
        """
        SELECT count(*) FROM orders o JOIN products p ON p.id = o.product_id
        WHERE o.total_cents <> o.quantity * p.price_cents
        """,
    )
    assert mismatches == 0


def test_planner_statistics_are_collected(warehouse: Warehouse) -> None:
    # The cost check relies on realistic planner estimates from the first query.
    estimated = _scalar(
        warehouse.admin_dsn, "SELECT reltuples::bigint FROM pg_class WHERE relname = 'orders'"
    )
    assert estimated == 1_000_000


def test_reader_can_select_every_table(warehouse: Warehouse) -> None:
    for table in ("products", "customers", "orders", "employee_salaries"):
        assert _scalar(warehouse.reader_dsn, f"SELECT count(*) > 0 FROM {table}") is True


def test_reader_sessions_default_to_read_only(warehouse: Warehouse) -> None:
    with (
        psycopg.connect(warehouse.reader_dsn) as conn,
        pytest.raises(errors.ReadOnlySqlTransaction),
    ):
        conn.execute("INSERT INTO products VALUES (999, 'x', 'toys', 1)")


def test_reader_cannot_write_even_with_read_only_turned_off(warehouse: Warehouse) -> None:
    with psycopg.connect(warehouse.reader_dsn) as conn:
        conn.execute("SET default_transaction_read_only = off")
        conn.commit()
        with pytest.raises(errors.InsufficientPrivilege):
            conn.execute("DELETE FROM orders WHERE id = 1")


def test_reader_cannot_create_tables(warehouse: Warehouse) -> None:
    with psycopg.connect(warehouse.reader_dsn) as conn:
        conn.execute("SET default_transaction_read_only = off")
        conn.commit()
        with pytest.raises(errors.InsufficientPrivilege):
            conn.execute("CREATE TABLE sneaky (id int)")
