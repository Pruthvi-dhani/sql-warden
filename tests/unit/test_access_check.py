import pytest

from sql_warden.config import EVERYTHING, ShapeConfig
from sql_warden.engines import Column, EngineUnavailable, Table
from sql_warden.models import Decision
from sql_warden.profiles import Access
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine


def _table(schema: str, name: str, *columns: str) -> Table:
    return Table(schema, name, tuple(Column(column, "integer") for column in columns))


CATALOG = (
    _table("public", "products", "id", "name", "category", "price_cents"),
    _table("public", "customers", "id", "full_name", "email", "ssn"),
    # orders.name is not for the public profile, while products.name is: a correlated
    # subquery must not get one through the other.
    _table("public", "orders", "id", "product_id", "quantity", "name"),
    _table("public", "employee_salaries", "id", "salary_cents"),
    _table("public", "MixedCase", "Id", "low"),
    _table("reports", "daily", "day", "total"),
)
PUBLIC = Access(
    {
        ("public", "products"): frozenset({"id", "name", "price_cents"}),
        ("public", "orders"): frozenset({"id", "product_id", "quantity"}),
        ("reports", "daily"): EVERYTHING,
    }
)
ADMIN = Access(EVERYTHING)
# Allowed by the shape check, so the access check is what sees them.
SHAPE = ShapeConfig(allowed_functions=("to_jsonb", "row_to_json"))


def _decide(sql: str, access: Access | None = PUBLIC, profile: str = "public") -> Decision:
    warden = Warden(FakeEngine(catalog=CATALOG), shape=SHAPE, profile=profile, access=access)
    return warden.check(sql)


def _refusal(sql: str, access: Access | None = PUBLIC) -> tuple[str, str]:
    refused_by = _decide(sql, access).refused_by
    assert refused_by is not None, f"allowed: {sql}"
    assert refused_by.check == "access"
    assert refused_by.refusal is not None
    return refused_by.refusal.code, refused_by.refusal.reason


@pytest.mark.parametrize(
    ("sql", "runs"),
    [
        ("select id, name from products", "SELECT id, name FROM public.products LIMIT 101"),
        ("select ID from PRODUCTS", "SELECT id FROM public.products LIMIT 101"),
        (
            "select p.name, sum(o.quantity) from products p join orders o on o.product_id = p.id "
            "group by p.name",
            "SELECT p.name, SUM(o.quantity) FROM public.products AS p JOIN public.orders AS o "
            "ON o.product_id = p.id GROUP BY p.name LIMIT 101",
        ),
        ("select name n from products order by n", None),
        (
            "select name, count(*) c from products group by name having count(*) > 1 order by c",
            None,
        ),
        (
            "with x as (select id, name from products) select name from x",
            "WITH x AS (SELECT id, name FROM public.products) SELECT name FROM x LIMIT 101",
        ),
        # Unquoted names fold before CTEs are matched, as in Postgres.
        ("with X as (select id from products) select * from x", None),
        ("select * from (select id, name from products) t", None),
        ("select id from products where id in (select product_id from orders)", None),
        ("select id from products p where exists (select 1 from orders o where o.id = p.id)", None),
        ("select id from products union select product_id from orders order by id", None),
        ("select * from reports.daily", "SELECT * FROM reports.daily LIMIT 101"),
        ("select d.* from reports.daily d", None),
        ("select count(*) from products", None),
        ("select g from generate_series(1, 3) g", None),
        ("select 1", "SELECT 1 LIMIT 101"),
        ("select p.id from products p join orders o using (id)", None),
        # sqlglot leaves DISTINCT ON unqualified: an output name, or the one table with it.
        ("select distinct on (name) name, id from products order by name, id", None),
        ("select distinct on (name) id from products order by name, id", None),
        ("select id from public.products", "SELECT id FROM public.products LIMIT 101"),
    ],
)
def test_allowed(sql: str, runs: str | None) -> None:
    decision = _decide(sql)
    assert decision.allowed, decision.refused_by
    assert [step.check for step in decision.trace] == ["parse", "shape", "access"]
    if runs is not None:
        assert decision.sql == runs


TABLE = "TABLE_NOT_ALLOWED"
COLUMN = "COLUMN_NOT_ALLOWED"
STAR = "STAR_NOT_ALLOWED"


@pytest.mark.parametrize(
    ("sql", "code", "reason"),
    [
        (
            "select * from employee_salaries",
            TABLE,
            "table public.employee_salaries is not available to profile public",
        ),
        # A table that doesn't exist gets the same answer: no probing for names.
        ("select * from nosuch", TABLE, "table public.nosuch is not available to profile public"),
        ("select count(*) from customers", TABLE, "table public.customers is not available"),
        ("select id from products where exists (select 1 from customers)", TABLE, "customers"),
        ("with x as (select email from customers) select * from x", TABLE, "customers"),
        ("select 1 from information_schema.tables", TABLE, "table information_schema.tables"),
        ("select * from pg_tables", TABLE, "table public.pg_tables"),
        ("select * from warehouse.public.products", TABLE, "names a database; use schema.table"),
        ('select * from "MixedCase"', TABLE, "table public.MixedCase"),
        ("select category from products", COLUMN, "column category is not available"),
        # A column that doesn't exist gets the same answer.
        ("select nope from products", COLUMN, "column nope is not available to profile public"),
        ("select p.category from products p", COLUMN, "column category"),
        # Columns only filtered, grouped or sorted on can leak as much as selected ones.
        ("select id from products where category = 'x'", COLUMN, "column category"),
        ("select id from products order by category", COLUMN, "column category"),
        ("select count(*) from products group by category", COLUMN, "column category"),
        ("select max(o.name) from orders o", COLUMN, "column name"),
        # Postgres reads o.name here (inner scope first), not products.name.
        (
            "select id from products p where exists (select 1 from orders o where name = 'x')",
            COLUMN,
            "column name",
        ),
        (
            "select * from products",
            STAR,
            "* reads every column of public.products, but profile public may read only "
            "id, name, price_cents; list the columns instead",
        ),
        ("select p.* from products p", STAR, "p.* reads every column of public.products"),
        ("select to_jsonb(p.*) from products p", STAR, "p.* reads every column"),
        # A table alias on its own is the whole row.
        ("select row_to_json(p) from products p", STAR, "p reads every column of"),
        ("select p from products p", STAR, "p reads every column of"),
        ("select id from products natural join orders", COLUMN, "NATURAL JOIN"),
        # Renaming by position: x.name here would be category.
        ("select x.name from products x(a, b, name)", COLUMN, "renames the table's columns"),
        ("select lower(p::text) from products p", STAR, "p reads every column of"),
        ("select id from products p, lateral (select category) x", COLUMN, "column category"),
        ("select distinct on (category) id from products", COLUMN, "column category"),
        ("select distinct on (o.name) o.id from orders o", COLUMN, "column name"),
        # Two sources have id: ambiguous, as for Postgres.
        ("select distinct on (id) 1 from products, orders", COLUMN, "column id"),
        ("select id, rank() over (order by category) from products", COLUMN, "column category"),
        ("select xmin from products", COLUMN, "column xmin"),
        ("select id from products where (id, category) = (1, 'x')", COLUMN, "column category"),
        ("select id from (select * from products) t", STAR, "* reads every column"),
        ("select products.id from products p", COLUMN, "products is not a table this query"),
    ],
)
def test_refused(sql: str, code: str, reason: str) -> None:
    refused_code, refused_reason = _refusal(sql)
    assert refused_code == code
    assert reason in refused_reason


class TestEveryTable:
    def test_reads_any_table_and_star(self) -> None:
        decision = _decide("select * from employee_salaries", ADMIN, "admin")
        assert decision.sql == "SELECT * FROM public.employee_salaries LIMIT 101"

    @pytest.mark.parametrize(
        ("sql", "code"),
        [
            ("select nope from products", COLUMN),
            ("select * from nosuch", TABLE),
            ("select * from information_schema.tables", TABLE),
        ],
    )
    def test_still_only_what_the_role_can_read(self, sql: str, code: str) -> None:
        assert _refusal(sql, ADMIN)[0] == code

    def test_quoted_names_keep_their_case(self) -> None:
        assert _decide('select "Id", low from "MixedCase"', ADMIN, "admin").allowed


class TestNoRules:
    def test_the_implicit_profile_has_no_access_check(self) -> None:
        decision = _decide("select * from employee_salaries", access=None, profile="all")
        assert [step.check for step in decision.trace] == ["parse", "shape"]
        assert decision.sql == "SELECT * FROM employee_salaries LIMIT 101"

    def test_a_profile_that_lists_no_tables_reads_nothing(self) -> None:
        assert _refusal("select id from products", Access({}))[0] == TABLE

    def test_queries_without_tables_still_run(self) -> None:
        assert _decide("select 1 + 1", Access({})).allowed


def test_an_unreadable_catalog_refuses_rather_than_guesses() -> None:
    engine = FakeEngine(error=EngineUnavailable("could not connect to the database"))
    decision = Warden(engine, profile="public", access=PUBLIC).check("select id from products")
    refused_by = decision.refused_by
    assert refused_by is not None
    assert refused_by.refusal is not None
    assert refused_by.refusal.code == "CATALOG_UNAVAILABLE"
    assert "could not connect" in refused_by.refusal.reason


def test_refusals_happen_before_anything_runs() -> None:
    engine = FakeEngine(catalog=CATALOG)
    outcome = Warden(engine, profile="public", access=PUBLIC).run("select * from employee_salaries")
    assert outcome.result is None
    assert engine.executed == []
