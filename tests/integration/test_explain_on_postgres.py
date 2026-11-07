"""PostgresEngine.explain() against the seeded warehouse: estimates, and that nothing runs."""

import contextlib
import time

import psycopg
import pytest

from sql_warden.audit import MemoryAuditSink
from sql_warden.engines import EngineUnavailable, QueryFailed
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration


def test_an_indexed_lookup_is_cheap(warehouse: Warehouse) -> None:
    estimate = PostgresEngine(warehouse.reader_dsn).explain(
        "SELECT * FROM orders WHERE id = 42 LIMIT 101"
    )
    assert estimate.total_cost < 100
    assert estimate.est_rows == 1
    assert estimate.top_node == "Index Scan using orders_pkey on orders"
    assert estimate.raw["Plan"]["Node Type"] == "Limit"


def test_a_cross_join_is_expensive(warehouse: Warehouse) -> None:
    # Counting it means reading all 10^12 pairs: no LIMIT can cut that short.
    engine = PostgresEngine(warehouse.reader_dsn)
    estimate = engine.explain("SELECT COUNT(*) FROM orders AS a CROSS JOIN orders AS b LIMIT 101")
    assert estimate.total_cost > 1e9
    assert estimate.top_node == "Nested Loop"
    lookup = engine.explain("SELECT * FROM orders WHERE id = 42 LIMIT 101")
    assert estimate.total_cost > 1e7 * lookup.total_cost


def test_a_full_scan_is_named_after_its_table(warehouse: Warehouse) -> None:
    estimate = PostgresEngine(warehouse.reader_dsn).explain("SELECT SUM(quantity) FROM orders")
    assert "Seq Scan on orders" in estimate.top_node  # "Parallel Seq Scan" with parallel workers
    assert estimate.est_rows == 1


def test_it_explains_the_sql_a_check_approved(warehouse: Warehouse) -> None:
    # What the cost check will do: explain the regenerated SQL, LIMIT and all.
    engine = PostgresEngine(warehouse.reader_dsn, max_rows=100)
    decision = Warden(engine, audit=MemoryAuditSink()).check(
        "select o.id, c.email from orders o join customers c on c.id = o.customer_id -- hi"
    )
    assert decision.sql is not None
    estimate = engine.explain(decision.sql)
    assert estimate.est_rows == 101  # the LIMIT the shape check added: row cap + 1
    assert estimate.raw["Plan"]["Node Type"] == "Limit"


def test_the_query_is_never_run(warehouse: Warehouse) -> None:
    started = time.perf_counter()
    estimate = PostgresEngine(warehouse.reader_dsn).explain("SELECT pg_sleep(5)")
    assert time.perf_counter() - started < 2
    assert estimate.top_node == "Result"


def test_explaining_a_write_changes_nothing(warehouse: Warehouse) -> None:
    # The checks never send one, but even the admin role's DELETE is only planned, and a
    # statement stacked after the one explained is refused rather than run.
    engine = PostgresEngine(warehouse.admin_dsn)
    with contextlib.suppress(QueryFailed):  # the read-only transaction may refuse it: fine
        engine.explain("DELETE FROM products")
    for sql in ("SELECT 1; DELETE FROM products", "DELETE FROM products; SELECT 1"):
        with pytest.raises(QueryFailed, match="cannot insert multiple commands"):
            engine.explain(sql)
    with psycopg.connect(warehouse.admin_dsn) as conn:
        assert conn.execute("SELECT count(*) FROM products").fetchone() == (200,)


@pytest.mark.parametrize(
    "sql", ["EXPLAIN ANALYZE SELECT pg_sleep(5)", "ANALYZE orders", "ANALYZE SELECT pg_sleep(5)"]
)
def test_the_sql_cant_make_it_explain_analyze(warehouse: Warehouse, sql: str) -> None:
    started = time.perf_counter()
    with pytest.raises(QueryFailed) as caught:
        PostgresEngine(warehouse.admin_dsn).explain(sql)
    assert caught.value.sqlstate == "42601"  # syntax_error
    assert time.perf_counter() - started < 2


def test_errors_point_into_the_sql_as_sent(warehouse: Warehouse) -> None:
    with pytest.raises(QueryFailed) as caught:
        PostgresEngine(warehouse.reader_dsn).explain("SELECT nope FROM products")
    message = str(caught.value)
    assert message.splitlines()[:3] == [
        'column "nope" does not exist',
        "  SELECT nope FROM products",
        "         ^",
    ]
    assert "EXPLAIN" not in message


def test_a_table_the_role_cant_read(warehouse: Warehouse) -> None:
    with pytest.raises(QueryFailed) as caught:
        PostgresEngine(warehouse.public_dsn).explain("SELECT * FROM employee_salaries")
    assert caught.value.sqlstate == "42501"  # insufficient_privilege


def test_an_unreachable_database() -> None:
    engine = PostgresEngine("postgresql://nobody:x@127.0.0.1:1/none", connect_timeout_s=2)
    with pytest.raises(EngineUnavailable, match="could not connect"):
        engine.explain("SELECT 1")
