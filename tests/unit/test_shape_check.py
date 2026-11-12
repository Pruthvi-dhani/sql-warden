import pytest

from sql_warden.config import ShapeConfig
from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline import CheckContext, ParseCheck, ShapeCheck
from tests.unit import dialects

pytestmark = pytest.mark.usefixtures("dialect")  # every test here runs under each dialect
PG = pytest.mark.postgres_only
C = RefusalCode


def _check(
    sql: str, rules: ShapeConfig | None = None, *, max_rows: int = 100
) -> tuple[CheckContext, Refusal | None]:
    """Parse and shape-check sql. Parsing must succeed: these tests are about shape."""
    ctx = CheckContext(sql=sql, dialect=dialects.current())
    assert ParseCheck().run(ctx) is None
    return ctx, ShapeCheck(rules or ShapeConfig(), max_rows=max_rows).run(ctx)


def _refusal(sql: str, rules: ShapeConfig | None = None) -> Refusal | None:
    return _check(sql, rules)[1]


def _rewritten(
    sql: str, rules: ShapeConfig | None = None, *, max_rows: int = 100
) -> tuple[str, list[str]]:
    """The SQL that would run, and the rewrite notes, for an allowed query."""
    ctx, refusal = _check(sql, rules, max_rows=max_rows)
    assert refusal is None, refusal
    return dialects.text(ctx.sql_to_run()), ctx.rewrites


@pytest.mark.parametrize(
    "sql",
    [
        "select id, name from products",
        "select count(*), max(price_cents) from products",
        "select p.name, o.quantity from orders o join products p on p.id = o.product_id",
        "select * from customers c left join orders o on o.customer_id = c.id",
        "select id from products union select id from orders",
        "select id from products intersect select product_id from orders",
        "select id from products except all select product_id from orders",
        "with big as (select * from orders where quantity > 3) select count(*) from big",
        "with recursive n(i) as (select 1 union all select i + 1 from n where i < 5) "
        "select * from n",
        "select * from (select id from products) p",
        "select id from customers where id in (select customer_id from orders)",
        "select exists (select 1 from orders where customer_id = 1)",
        "(select id from products)",
        "select date_trunc('day', ordered_at), count(*) from orders group by 1",
        "select coalesce(email, 'none'), lower(name), current_date from customers",
        pytest.param("select now()", marks=PG),  # not a function Snowflake has
        "select string_agg(name, ', ') from products",
        "select * from generate_series(1, 10)",
        "select id::text, price_cents / 100.0 from products",
        "select distinct on (customer_id) * from orders order by customer_id, ordered_at desc",
        "select row_number() over (partition by customer_id order by id) from orders",
        "select current_user, current_database()",
        "select id from products order by id limit 10 offset 20",
        "select id from products fetch first 5 rows only",
    ],
)
def test_reads_are_allowed(sql: str) -> None:
    assert _refusal(sql) is None


@pytest.mark.parametrize(
    ("sql", "code", "reason"),
    [
        (
            "select 1; select 2",
            C.MULTIPLE_STATEMENTS,
            "send one statement at a time; this query has 2",
        ),
        ("select 1; delete from orders", C.MULTIPLE_STATEMENTS, None),
        ("delete from orders", C.NOT_A_SELECT, "only SELECT queries are allowed, not DELETE"),
        ("insert into products (id) values (1)", C.NOT_A_SELECT, "not INSERT"),
        ("update products set price_cents = 0", C.NOT_A_SELECT, "not UPDATE"),
        ("merge into t using s on true when matched then delete", C.NOT_A_SELECT, "not MERGE"),
        ("drop table orders", C.NOT_A_SELECT, "not DROP"),
        ("create table x (a int)", C.NOT_A_SELECT, "not CREATE"),
        ("alter table orders add column x int", C.NOT_A_SELECT, "not ALTER"),
        ("truncate orders", C.NOT_A_SELECT, "not TRUNCATE"),
        ("grant select on orders to public", C.NOT_A_SELECT, "not GRANT"),
        ("copy orders to stdout", C.NOT_A_SELECT, "not COPY"),
        ("set statement_timeout = 0", C.NOT_A_SELECT, "not SET"),
        ("begin", C.NOT_A_SELECT, "not BEGIN"),
        pytest.param("do $$ begin perform 1; end $$", C.NOT_A_SELECT, "not DO", marks=PG),
        ("explain analyze select 1", C.NOT_A_SELECT, "not EXPLAIN"),
        ("call some_procedure()", C.NOT_A_SELECT, "not CALL"),
        ("values (1), (2)", C.NOT_A_SELECT, "not VALUES"),
        ("table orders", C.NOT_A_SELECT, "only SELECT queries are allowed"),
        # Postgres lets a CTE write; in Snowflake this isn't SQL at all (a parse error).
        pytest.param(
            "with gone as (delete from orders returning *) select count(*) from gone",
            C.NOT_READ_ONLY,
            "the query contains a DELETE in the CTE gone; queries must not modify data",
            marks=PG,
        ),
        pytest.param(
            "with x as (update products set price_cents = 0 returning id) select * from x",
            C.NOT_READ_ONLY,
            "UPDATE in the CTE x",
            marks=PG,
        ),
        (
            "select * into stolen from customers",
            C.NOT_READ_ONLY,
            "SELECT ... INTO creates a table; queries must not modify data",
        ),
        (
            "select * from orders for update",
            C.NOT_READ_ONLY,
            "FOR UPDATE locks rows; queries must not take locks",
        ),
        pytest.param(
            "select * from orders for share", C.NOT_READ_ONLY, "FOR SHARE locks rows", marks=PG
        ),
        pytest.param(
            "select * from orders for update skip locked",
            C.NOT_READ_ONLY,
            "FOR UPDATE SKIP LOCKED",
            marks=PG,
        ),
        # Each dialect has its own list of these; unknown to the other, it is refused there
        # too, as any function sql-warden doesn't know.
        pytest.param(
            "select pg_sleep(60)",
            C.FUNCTION_NOT_ALLOWED,
            "pg_sleep() is never allowed: it can act on the server, or read what the checks "
            "can't see",
            marks=PG,
        ),
        ("select pg_sleep(60)", C.FUNCTION_NOT_ALLOWED, "pg_sleep()"),
        ("select pg_catalog.pg_sleep(1)", C.FUNCTION_NOT_ALLOWED, "pg_sleep()"),
        ('select "pg_sleep"(1)', C.FUNCTION_NOT_ALLOWED, "pg_sleep()"),
        ("select PG_SLEEP_FOR('1 minute')", C.FUNCTION_NOT_ALLOWED, "pg_sleep_for()"),
        ("select pg_read_file('/etc/passwd')", C.FUNCTION_NOT_ALLOWED, "pg_read_file()"),
        ("select * from pg_ls_dir('.')", C.FUNCTION_NOT_ALLOWED, "pg_ls_dir()"),
        ("select lo_import('/etc/passwd')", C.FUNCTION_NOT_ALLOWED, "lo_import()"),
        ("select * from dblink('host=x', 'select 1') t(a int)", C.FUNCTION_NOT_ALLOWED, "dblink()"),
        ("select set_config('statement_timeout', '0', false)", C.FUNCTION_NOT_ALLOWED, None),
        ("select current_setting('data_directory')", C.FUNCTION_NOT_ALLOWED, None),
        ("select pg_terminate_backend(1)", C.FUNCTION_NOT_ALLOWED, None),
        ("select pg_advisory_lock(1)", C.FUNCTION_NOT_ALLOWED, None),
        ("select nextval('orders_id_seq')", C.FUNCTION_NOT_ALLOWED, None),
        # Runs SQL given as a string, which no check would ever see.
        (
            "select query_to_xml('select * from employee_salaries', true, true, '')",
            C.FUNCTION_NOT_ALLOWED,
            None,
        ),
        ("select table_to_xml('employee_salaries', true, true, '')", C.FUNCTION_NOT_ALLOWED, None),
        # Hidden deeper in the query.
        (
            "select id from products where id = (select pg_sleep(1)::int)",
            C.FUNCTION_NOT_ALLOWED,
            None,
        ),
        ("with x as (select pg_sleep(1)) select * from x", C.FUNCTION_NOT_ALLOWED, None),
        ("select 1 union select pg_sleep(1)::int", C.FUNCTION_NOT_ALLOWED, None),
        ("select * from orders order by pg_sleep(0.1)", C.FUNCTION_NOT_ALLOWED, None),
        (
            "select age(created_at) from customers",
            C.FUNCTION_NOT_ALLOWED,
            "age() is not a standard SQL function sql-warden knows; "
            "it must be listed in shape.allowed_functions",
        ),
        (
            "select * from a join b using (x) join c using (x) join d using (x) "
            "join e using (x) join f using (x)",
            C.TOO_MANY_JOINS,
            "the query has 5 joins; at most 4 are allowed (shape.max_joins)",
        ),
        ("select * from a, b, c, d, e, f", C.TOO_MANY_JOINS, "the query has 5 joins"),
        (
            "select * from (select * from (select * from (select * from (select 1) a) b) c) d",
            C.SUBQUERY_TOO_DEEP,
            "subqueries and CTEs nest 4 levels deep; at most 3 are allowed "
            "(shape.max_subquery_depth)",
        ),
        ("select 1 limit all", C.INVALID_LIMIT, "the LIMIT must be a whole number, not ALL"),
        ("select 1 limit null", C.INVALID_LIMIT, "not NULL"),
        ("select 1 limit 2 + 3", C.INVALID_LIMIT, "not 2 + 3"),
        ("select 1 limit (select 5)", C.INVALID_LIMIT, "not (SELECT 5)"),
        ("select 1 limit 10.5", C.INVALID_LIMIT, "not 10.5"),
        ("select 1 fetch first 10 percent rows only", C.INVALID_LIMIT, "FETCH ... PERCENT"),
        ("select 1 fetch first 5 rows with ties", C.INVALID_LIMIT, "WITH TIES"),
    ],
)
def test_refusals_have_a_code_and_a_specific_reason(
    sql: str, code: RefusalCode, reason: str | None
) -> None:
    refusal = _refusal(sql)
    assert refusal is not None, f"{sql!r} was allowed"
    assert refusal.code is code
    if reason is not None:
        assert reason in dialects.text(refusal.reason)


class TestLimits:
    def test_missing_limit_is_added_one_past_the_row_cap(self) -> None:
        assert _rewritten("select id from products order by id") == (
            "SELECT id FROM products ORDER BY id LIMIT 101",
            ["added LIMIT 101 (row cap 100 + 1 to detect truncation)"],
        )

    def test_limit_above_the_cap_is_lowered(self) -> None:
        assert _rewritten("select id from products limit 5000 offset 10") == (
            "SELECT id FROM products LIMIT 101 OFFSET 10",
            ["lowered LIMIT 5000 to 101 (row cap 100 + 1 to detect truncation)"],
        )

    @pytest.mark.parametrize("limit", [0, 1, 100, 101])
    def test_limit_within_the_cap_is_left_alone(self, limit: int) -> None:
        assert _rewritten(f"select id from products limit {limit}") == (
            f"SELECT id FROM products LIMIT {limit}",
            [],
        )

    @pytest.mark.parametrize(
        ("sql", "expected"),
        [
            (
                "select id from products fetch first 500 rows only",
                "SELECT id FROM products LIMIT 101",
            ),
            (
                "select id from products union select id from orders",
                "SELECT id FROM products UNION SELECT id FROM orders LIMIT 101",
            ),
            # An inner LIMIT does not bound the result, so the outer query still gets one.
            (
                "select * from (select id from orders limit 5000) o",
                "SELECT * FROM (SELECT id FROM orders LIMIT 5000) AS o LIMIT 101",
            ),
            (
                "(select id from orders limit 5000)",
                "(SELECT id FROM orders LIMIT 5000) LIMIT 101",
            ),
            (
                "with x as (select id from orders) select * from x",
                "WITH x AS (SELECT id FROM orders) SELECT * FROM x LIMIT 101",
            ),
        ],
    )
    def test_the_limit_goes_on_the_whole_result(self, sql: str, expected: str) -> None:
        assert _rewritten(sql)[0] == expected

    def test_fetch_first_row_only_means_one(self) -> None:
        assert _rewritten("select id from products fetch first row only")[1] == []

    def test_row_cap_comes_from_the_engine_setting(self) -> None:
        assert _rewritten("select id from products", max_rows=7)[0] == (
            "SELECT id FROM products LIMIT 8"
        )

    def test_require_refuses_a_missing_limit(self) -> None:
        refusal = _refusal("select id from products", ShapeConfig(limit="require"))
        assert refusal == Refusal(
            C.LIMIT_REQUIRED, "the query has no LIMIT; add one of at most 100 (the row cap)"
        )

    def test_require_refuses_a_limit_above_the_cap(self) -> None:
        refusal = _refusal("select id from products limit 101", ShapeConfig(limit="require"))
        assert refusal == Refusal(C.LIMIT_TOO_HIGH, "LIMIT 101 is above the row cap of 100")

    def test_require_never_rewrites(self) -> None:
        assert (
            _rewritten("select id from products limit 100", ShapeConfig(limit="require"))[1] == []
        )

    def test_refused_queries_are_not_rewritten(self) -> None:
        assert _check("select pg_sleep(1)")[0].rewrites == []


class TestFunctionPolicy:
    def test_allowed_functions_extend_what_sqlglot_knows(self) -> None:
        rules = ShapeConfig(allowed_functions=("age",))
        assert _refusal("select age(created_at) from customers", rules) is None

    def test_allowed_functions_are_case_insensitive(self) -> None:
        rules = ShapeConfig(allowed_functions=("AGE",))
        assert _refusal("select Age(created_at) from customers", rules) is None

    def test_denied_functions_take_glob_patterns(self) -> None:
        rules = ShapeConfig(denied_functions=("regexp_*",))
        assert _refusal("select regexp_replace(name, 'a', 'b') from products", rules) == Refusal(
            C.FUNCTION_NOT_ALLOWED,
            "regexp_replace() is denied by shape.denied_functions ('regexp_*')",
        )

    def test_known_functions_can_be_denied_too(self) -> None:
        rules = ShapeConfig(denied_functions=("md5",))
        refusal = _refusal("select md5(email) from customers", rules)
        assert refusal is not None
        assert refusal.code is C.FUNCTION_NOT_ALLOWED


class TestJoinsAndNesting:
    def test_join_limit_is_inclusive(self) -> None:
        rules = ShapeConfig(max_joins=2)
        assert _refusal("select * from a join b on true join c on true", rules) is None
        refusal = _refusal("select * from a join b on true join c on true join d on true", rules)
        assert refusal is not None
        assert refusal.code is C.TOO_MANY_JOINS

    def test_joins_are_counted_across_the_whole_query(self) -> None:
        rules = ShapeConfig(max_joins=1)
        refusal = _refusal(
            "select * from a join b on true where x in (select y from c join d on true)", rules
        )
        assert refusal is not None
        assert refusal.reason.startswith("the query has 2 joins")

    def test_no_joins_allowed(self) -> None:
        refusal = _refusal("select * from a cross join b", ShapeConfig(max_joins=0))
        assert refusal is not None
        assert refusal.reason.startswith("the query has 1 join;")

    @pytest.mark.parametrize(
        ("sql", "depth"),
        [
            ("select 1", 0),
            ("(select 1)", 0),
            ("select 1 union select 2 union select 3", 0),
            ("select * from (select 1) a", 1),
            ("with x as (select 1) select * from x", 1),
            ("with x as (select 1), y as (select * from x) select * from y", 1),
            ("select * from t where a in (select b from u where c = (select max(d) from v))", 2),
            ("select * from t, lateral (select * from (select 1) y) x", 2),
            ("select * from (select 1 union select * from (select 2) b) a", 2),
        ],
    )
    def test_depth_counts_nesting_not_neighbours(self, sql: str, depth: int) -> None:
        assert _refusal(sql, ShapeConfig(max_subquery_depth=depth)) is None
        if depth > 0:
            refusal = _refusal(sql, ShapeConfig(max_subquery_depth=depth - 1))
            assert refusal is not None
            assert refusal.code is C.SUBQUERY_TOO_DEEP
