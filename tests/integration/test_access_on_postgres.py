"""The access check against the seeded warehouse and its real catalog."""

from collections.abc import Iterator

import psycopg
import pytest

from sql_warden.config import EVERYTHING
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.profiles import Access
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration

PUBLIC = Access({("public", "products"): frozenset({"id", "name", "price_cents"})})
ADMIN = Access(EVERYTHING)


def _admin(warehouse: Warehouse) -> Warden:
    return Warden(PostgresEngine(warehouse.reader_dsn), profile="admin", access=ADMIN)


@pytest.mark.parametrize(
    "sql",
    [
        "select count(*) from employee_salaries",
        "select email from customers",
        "select category from products",
        "select * from products",
    ],
)
def test_admin_may_and_public_may_not(warehouse: Warehouse, sql: str) -> None:
    public = Warden(PostgresEngine(warehouse.public_dsn), profile="public", access=PUBLIC)
    assert _admin(warehouse).run(sql).result is not None
    refused = public.run(sql)
    assert refused.result is None
    refused_by = refused.decision.refused_by
    assert refused_by is not None
    assert refused_by.check == "access"


@pytest.mark.parametrize(
    "sql",
    [
        "select id, name from products where id <= 3 order by id",
        "with top as (select product_id, sum(quantity) as q from orders group by product_id) "
        "select p.name, t.q from top t join products p on p.id = t.product_id "
        "order by t.q desc, p.name limit 5",
        "select p.id from products p join orders o using (id) where p.id <= 3 order by 1",
        "select id from products p where exists (select 1 from orders o "
        "where o.product_id = p.id and o.quantity > 4) order by id limit 5",
        "select country, count(*) from customers group by country order by 2 desc, 1 limit 5",
        "select g, g * 2 from generate_series(1, 3) g",
        "select id from products union select id from employee_salaries order by id limit 5",
        "select distinct on (country) country, id from customers order by country, id limit 5",
        "select id, rank() over (order by price_cents desc) from products order by 2, 1 limit 3",
        "select p.id, c.n from products p cross join lateral "
        "(select count(*) as n from orders o where o.product_id = p.id) c order by p.id limit 3",
        "select count(*) filter (where status = 'shipped') from orders",
        "select * from products where id = 1",
    ],
)
def test_what_runs_returns_what_the_query_asked_for(warehouse: Warehouse, sql: str) -> None:
    # The checked query runs with its tables pinned to their schema; nothing else changes.
    outcome = _admin(warehouse).run(sql)
    assert outcome.result is not None, outcome.decision.refused_by or outcome.error
    raw = PostgresEngine(warehouse.reader_dsn).execute(sql)
    assert (outcome.result.columns, outcome.result.rows) == (raw.columns, raw.rows)


@pytest.fixture
def decoy(warehouse: Warehouse) -> Iterator[None]:
    """A schema named after the reader role. Postgres's default search_path ("$user", public)
    puts it first, so an unqualified `products` would read the decoy."""
    with psycopg.connect(warehouse.admin_dsn, autocommit=True) as conn:
        conn.execute("CREATE SCHEMA warden_reader")
        conn.execute("CREATE TABLE warden_reader.products (id integer)")
        conn.execute("INSERT INTO warden_reader.products VALUES (1)")
        conn.execute("GRANT USAGE ON SCHEMA warden_reader TO warden_reader")
        conn.execute("GRANT SELECT ON warden_reader.products TO warden_reader")
    try:
        yield
    finally:
        with psycopg.connect(warehouse.admin_dsn, autocommit=True) as conn:
            conn.execute("DROP SCHEMA warden_reader CASCADE")


def test_tables_are_pinned_to_the_schema_that_was_checked(
    warehouse: Warehouse, decoy: None
) -> None:
    sql = "select count(*) from products"
    assert PostgresEngine(warehouse.reader_dsn).execute(sql).rows == ((1,),)  # the decoy
    outcome = _admin(warehouse).run(sql)
    assert outcome.decision.sql == "SELECT COUNT(*) FROM public.products LIMIT 1001"
    assert outcome.result is not None
    assert outcome.result.rows == ((200,),)
