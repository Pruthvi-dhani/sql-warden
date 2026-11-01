import time

import psycopg
import pytest

from sql_warden.config import ShapeConfig
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.models import RefusalCode
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "sql",
    [
        "select id::text, price_cents / 100.0 as price from products order by id",
        "select full_name from customers "
        "where email ilike 'CUSTOMER1@%' and country = any(array['GB'])",
        "select distinct on (customer_id) customer_id, id from orders "
        "order by customer_id, id desc",
        "select date_trunc('month', ordered_at) m, count(*) filter (where quantity > 2) "
        "from orders group by 1 order by 1",
        "select extract(year from created_at), string_agg(full_name, ', ' order by full_name) "
        "from customers where id < 5 group by 1",
        "select $$it's$$ as quoted, E'tab\\there' as escaped, interval '1 day' * 2 as span",
        "select g, g % 2 = 0 as even from generate_series(1, 5) as g",
        "select id, row_number() over (partition by product_id order by ordered_at) from orders",
        "with recursive n(i) as (select 1 union all select i + 1 from n where i < 3) "
        "select * from n",
        "select coalesce(null, 'x'), nullif(1, 1), greatest(1, 2), now() > '2000-01-01'::date",
        "select jsonb_build_object('a', 1) ->> 'a'",
    ],
)
def test_regenerated_sql_runs_on_postgres(warehouse: Warehouse, sql: str) -> None:
    # The warden runs sqlglot's regeneration of the query, so it must be valid Postgres.
    shape = ShapeConfig(allowed_functions=("jsonb_build_object",))
    outcome = Warden(PostgresEngine(warehouse.reader_dsn), shape=shape).run(sql)
    assert outcome.result is not None, outcome.decision


def test_added_limit_still_reports_truncation(warehouse: Warehouse) -> None:
    outcome = Warden(PostgresEngine(warehouse.reader_dsn, max_rows=5)).run(
        "select id from orders order by id"
    )
    assert outcome.decision.sql == "SELECT id FROM orders ORDER BY id LIMIT 6"
    assert outcome.result is not None
    assert [row[0] for row in outcome.result.rows] == [1, 2, 3, 4, 5]
    assert outcome.result.truncated is True


def test_a_lowered_limit_still_reports_truncation(warehouse: Warehouse) -> None:
    outcome = Warden(PostgresEngine(warehouse.reader_dsn, max_rows=5)).run(
        "select id from orders limit 1000000"
    )
    assert outcome.decision.rewrites == (
        "lowered LIMIT 1000000 to 6 (row cap 5 + 1 to detect truncation)",
    )
    assert outcome.result is not None
    assert len(outcome.result.rows) == 5
    assert outcome.result.truncated is True


def test_a_limit_within_the_cap_is_not_truncated(warehouse: Warehouse) -> None:
    outcome = Warden(PostgresEngine(warehouse.reader_dsn, max_rows=5)).run(
        "select id from orders limit 5"
    )
    assert outcome.result is not None
    assert len(outcome.result.rows) == 5
    assert outcome.result.truncated is False


def test_small_results_are_complete(warehouse: Warehouse) -> None:
    outcome = Warden(PostgresEngine(warehouse.reader_dsn, max_rows=100)).run(
        "select id from employee_salaries"
    )
    assert outcome.result is not None
    assert len(outcome.result.rows) == 50
    assert outcome.result.truncated is False


def test_shape_refusals_stop_queries_the_admin_role_could_run(warehouse: Warehouse) -> None:
    # The admin role can write, so only the shape check stands between it and the data here.
    warden = Warden(PostgresEngine(warehouse.admin_dsn))
    for sql, code in [
        ("with x as (delete from products returning id) select count(*) from x", "NOT_READ_ONLY"),
        ("select * from products for update", "NOT_READ_ONLY"),
        ("select 1; delete from products", "MULTIPLE_STATEMENTS"),
    ]:
        refused_by = warden.run(sql).decision.refused_by
        assert refused_by is not None
        assert refused_by.refusal is not None
        assert refused_by.refusal.code == RefusalCode(code)
    with psycopg.connect(warehouse.admin_dsn) as conn:
        assert conn.execute("select count(*) from products").fetchone() == (200,)


def test_pg_sleep_is_refused_before_it_reaches_the_database(warehouse: Warehouse) -> None:
    started = time.perf_counter()
    outcome = Warden(PostgresEngine(warehouse.reader_dsn)).run("select pg_sleep(10)")
    assert outcome.result is None
    assert time.perf_counter() - started < 1
