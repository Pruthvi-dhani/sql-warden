"""Hostile queries: what someone sends who is trying to get past the checks.

Each is pinned to the refusal it must get, and none of them may reach the database, not even
its planner. The few that are allowed are here for what they are turned into: the query that
runs is written out again from what the checks read, so a comment, a string or an odd
character can't carry anything past them.

The profile is `support`: it reads customers (ssn and email masked), orders, and three
columns of products. employee_salaries exists and is not its to see.
"""

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from types import FrameType
from typing import Any

import pytest
import sqlglot
from sqlglot import exp
from sqlglot.dialects.dialect import Dialect

from sql_warden.audit import MemoryAuditSink
from sql_warden.config import ConfigError, MaskRule, ShapeConfig, parse_config
from sql_warden.engines import Column, Table
from sql_warden.models import Decision, RefusalCode
from sql_warden.pipeline.parse import MAX_LENGTH, MAX_NESTING, MAX_TYPE_NESTING
from sql_warden.profiles import Access
from sql_warden.warden import RECORDED_OF_TOO_LONG, Warden
from tests.unit.conftest import FakeEngine

C = RefusalCode
POSTGRES, SNOWFLAKE = "postgres", "snowflake"


def _table(name: str, *columns: str) -> Table:
    return Table("public", name, tuple(Column(column, "text") for column in columns))


CATALOG = (
    _table("customers", "id", "full_name", "email", "phone", "ssn"),
    _table("orders", "id", "customer_id", "quantity", "note"),
    _table("products", "id", "name", "category", "price_cents"),
    _table("employee_salaries", "id", "title", "salary_cents"),
)
READS: dict[tuple[str, str], Any] = {
    ("public", "customers"): "*",
    ("public", "orders"): "*",
    ("public", "products"): frozenset({"id", "name", "price_cents"}),
}
MASKS = {
    ("public", "customers", "ssn"): MaskRule.model_validate("redact"),
    ("public", "customers", "email"): MaskRule.model_validate("hmac"),
}


def _stored(name: str, dialect: str) -> str:
    return name.upper() if dialect == SNOWFLAKE else name


def _warden(dialect: str, shape: ShapeConfig | None = None) -> tuple[Warden, FakeEngine]:
    """The support profile's Warden, on a database that holds the names as dialect does."""

    def stored(name: str) -> str:
        return _stored(name, dialect)

    catalog = tuple(
        Table(
            stored(table.schema),
            stored(table.name),
            tuple(Column(stored(column.name), column.type) for column in table.columns),
        )
        for table in CATALOG
    )
    reads = {
        (stored(schema), stored(table)): (
            columns if columns == "*" else frozenset(stored(column) for column in columns)
        )
        for (schema, table), columns in READS.items()
    }
    masks = {tuple(stored(part) for part in column): rule for column, rule in MASKS.items()}
    engine = FakeEngine(catalog=catalog)
    warden = Warden(
        engine,
        audit=MemoryAuditSink(),
        dialect=dialect,
        shape=shape or ShapeConfig(),
        profile="support",
        access=Access(reads),
        masks=masks,  # type: ignore[arg-type]
        mask_key=b"k" * 32,
    )
    return warden, engine


def _code(decision: Decision) -> str | None:
    refused = decision.refused_by
    if refused is None:
        return None
    assert refused.refusal is not None
    return refused.refusal.code


def _refused(dialect: str, sql: str, code: RefusalCode) -> None:
    """sql is refused with code, whether it is only checked or sent to run, and the database
    never hears of it."""
    warden, engine = _warden(dialect)
    assert _code(warden.check(sql)) == code
    outcome = warden.run(sql)
    assert _code(outcome.decision) == code
    assert outcome.result is None
    assert (engine.explained, engine.executed) == ([], [])


def _cases(*groups: tuple[RefusalCode, list[str]]) -> list[Any]:
    return [pytest.param(sql, code, id=sql[:60]) for code, queries in groups for sql in queries]


class TestMoreThanOneStatement:
    @pytest.mark.parametrize(
        ("sql", "code"),
        _cases(
            (
                C.MULTIPLE_STATEMENTS,
                [
                    "select 1; drop table products",
                    "select 1; select 2",
                    "select 1 --\n; drop table products",
                    # A comment ends at a line break, and these are line breaks too.
                    "select 1 -- x\rfrom products; drop table products",
                    "select 1\u2028; drop table products",
                    "with x as (select 1) select * from x; drop table products",
                    # The string ends where the second $$ is, not where it seems to.
                    "select $$a$$; drop table products; --$$",
                    "select $x$ $$ ; $x$; delete from products",
                    # In Postgres a backslash does not escape a quote: the string ends here.
                    r"select 'a\'; drop table products; --'",
                ],
            ),
            # A semicolon only to the eye: the fullwidth one is no separator, and no SQL.
            (C.PARSE_ERROR, ["select 1 \uff1b drop table products"]),
        ),
    )
    def test_postgres(self, sql: str, code: RefusalCode) -> None:
        _refused(POSTGRES, sql, code)

    @pytest.mark.parametrize(
        ("sql", "code"),
        _cases(
            (
                C.MULTIPLE_STATEMENTS,
                [
                    "select 1; select 2",
                    "with x as (select 1) select * from x; drop table products",
                    # In Snowflake a backslash escapes: \\ is one, and the string ends.
                    r"select 'a\\'; delete from products; --'",
                ],
            ),
            # Snowflake's ->> runs one statement on another's result.
            (C.PARSE_ERROR, ["show tables ->> select * from $1", "select 1 ->> select 2"]),
        ),
    )
    def test_snowflake(self, sql: str, code: RefusalCode) -> None:
        _refused(SNOWFLAKE, sql, code)


class TestNotASelect:
    @pytest.mark.parametrize(
        ("sql", "code"),
        _cases(
            (
                C.NOT_A_SELECT,
                [
                    "copy products to stdout",
                    "copy (select * from employee_salaries) to '/tmp/x'",
                    "copy products from program 'rm -rf /'",
                    "do $$ begin delete from products; end $$",
                    "explain analyze delete from products",
                    "explain (analyze) select * from products",
                    "explain select * from employee_salaries",
                    "call do_something()",
                    "set statement_timeout = 0",
                    "set role postgres",
                    "set default_transaction_read_only = off",
                    "reset all",
                    "show server_version",
                    "listen x",
                    "notify x",
                    "vacuum",
                    "prepare p as delete from products",
                    "execute p",
                    "declare c cursor for select 1",
                    "begin",
                    "commit",
                    "lock table products",
                    "refresh materialized view x",
                    "create table x as select * from products",
                    "create temp table x (a int)",
                    "drop table products",
                    "alter table products add column x int",
                    "grant all on products to public",
                    "truncate products",
                    "insert into products values (1)",
                    "insert into products values (1) returning *",
                    "update products set name = 'x'",
                    "delete from products",
                    "merge into products p using orders o on p.id = o.id when matched then delete",
                    # Postgres's short way to write select * from.
                    "table employee_salaries",
                    "values (1), (2)",
                ],
            ),
            (C.PARSE_ERROR, ["analyze select 1"]),
        ),
    )
    def test_postgres(self, sql: str, code: RefusalCode) -> None:
        _refused(POSTGRES, sql, code)

    @pytest.mark.parametrize(
        ("sql", "code"),
        _cases(
            (
                C.NOT_A_SELECT,
                [
                    "call my_proc()",
                    "execute immediate 'delete from products'",
                    "execute immediate $$ delete from products $$",
                    "copy into @stage from products",
                    "put file:///etc/passwd @stage",
                    "get @stage file:///tmp",
                    "use role accountadmin",
                    "use secondary roles all",
                    "alter session set statement_timeout_in_seconds = 0",
                    "set x = 1",
                    "show tables",
                    "describe table products",
                    "create or replace table x as select 1",
                    "insert into products select * from products",
                    "merge into products using orders on true when matched then delete",
                    "truncate table products",
                ],
            ),
            (C.PARSE_ERROR, ["begin delete from products; end"]),
        ),
    )
    def test_snowflake(self, sql: str, code: RefusalCode) -> None:
        _refused(SNOWFLAKE, sql, code)


class TestASelectThatWrites:
    @pytest.mark.parametrize(
        "sql",
        [
            "with d as (delete from products returning *) select * from d",
            "with d as (insert into products values (1) returning id) select 1",
            "with d as (update products set name = 'x' returning id) select 1",
            "select * into newtable from products",
            "select * from products for update",
            "select * from products for share skip locked",
            "select * from products for no key update",
        ],
    )
    def test_postgres(self, sql: str) -> None:
        _refused(POSTGRES, sql, C.NOT_READ_ONLY)

    @pytest.mark.parametrize("sql", ["select * from products for update", "select seq.nextval"])
    def test_snowflake(self, sql: str) -> None:
        _refused(SNOWFLAKE, sql, C.NOT_READ_ONLY)


class TestForbiddenFunctions:
    @pytest.mark.parametrize(
        "sql",
        [
            # However it is spelled.
            "select pg_sleep(10)",
            "select PG_SLEEP(10)",
            'select "pg_sleep"(10)',
            "select pg_catalog.pg_sleep(10)",
            'select pg_catalog."pg_sleep"(10)',
            # Letters that only look the same are another function, and not one it knows.
            "select pg_sl\u200beep(10)",
            "select \uff50\uff47\uff3f\uff53\uff4c\uff45\uff45\uff50(10)",
            # Wherever it hides.
            "select coalesce(pg_sleep(10)::text, '')",
            "select 1 where (select pg_sleep(10)) is null",
            "select 1 order by pg_sleep(10)",
            "select 1 limit (select 1 from pg_sleep(1))",
            "select 1 offset (select count(*) from pg_sleep(10))",
            "select * from pg_sleep(10)",
            "select 1 from products join lateral pg_sleep(1) on true",
            "select case when true then pg_sleep(1) end",
            "select count(*) filter (where pg_sleep(1) is null) from products",
            "select sum(1) over (order by pg_sleep(1)) from products",
            "select array[pg_sleep(1)]",
            "select (pg_sleep(1)).*",
            # Settings: the statement timeout and the read-only transaction are two of them.
            "select set_config('statement_timeout', '0', false)",
            "select 1 from (select set_config('statement_timeout', '0', false)) x",
            "with c as (select set_config('default_transaction_read_only', 'off', false)) "
            "select * from c",
            "select pg_catalog.set_config('role', 'postgres', false)",
            "select current_setting('server_version')",
            # Files, the network, other queries.
            "select pg_read_file('/etc/passwd')",
            "select lo_import('/etc/passwd')",
            "select * from dblink('host=x', 'select 1') as t(a int)",
            "select query_to_xml('select * from employee_salaries', true, false, '')",
            "select table_to_xml('employee_salaries', true, false, '')",
            "select xpath('/x', query_to_xml('select 1', true, false, ''))",
            # What changes something without being a write.
            "select nextval('orders_id_seq')",
            "select setval('orders_id_seq', 1)",
            "select txid_current()",
            "select pg_advisory_lock(1)",
            "select pg_terminate_backend(1)",
            "select pg_notify('x', 'y')",
            # Whole rows as text or JSON, through a function.
            "select to_json(p) from products p",
            "select row_to_json(p) from products p",
        ],
    )
    def test_postgres(self, sql: str) -> None:
        _refused(POSTGRES, sql, C.FUNCTION_NOT_ALLOWED)

    @pytest.mark.parametrize(
        "sql",
        [
            "select system$wait(10)",
            "select SYSTEM$CANCEL_ALL_QUERIES(1)",
            'select "SYSTEM$WAIT"(10)',
            "select snowflake.core.something()",
            "select * from table(result_scan(last_query_id()))",
            "select * from table(information_schema.query_history())",
            "select get_ddl('table', 'employee_salaries')",
            "select all_user_names()",
            "select is_role_in_session('ACCOUNTADMIN')",
            # A table named by a string, where the access check can't read it.
            "select * from identifier('employee_salaries')",
            "select * from table('employee_salaries')",
            "select hash(*) from customers",
        ],
    )
    def test_snowflake(self, sql: str) -> None:
        _refused(SNOWFLAKE, sql, C.FUNCTION_NOT_ALLOWED)


class TestCasts:
    """Every table is also a type, and some types look names up: a cast can ask the catalog
    what the access check would never have answered."""

    @pytest.mark.parametrize(
        "sql",
        [
            # Is there such a table? It works only if there is.
            "select 'employee_salaries'::regclass",
            "select 'employee_salaries'::regclass::oid",
            "select regclass 'employee_salaries'",
            "select cast('employee_salaries' as regclass)",
            "select 'employee_salaries'::pg_catalog.regclass",
            "select 'pg_sleep(integer)'::regprocedure",
            "select 'postgres'::regrole",
            "select 'x'::regtype",
            "select 1::regconfig",
            # A table's row type: that it exists, and what its columns are called.
            "select null::employee_salaries",
            "select null::public.employee_salaries",
            "select cast(null as employee_salaries)",
            "select null::employee_salaries[]",
            "select '(1,x,1)'::employee_salaries",
            "select (null::employee_salaries).*",
            "select (null::products).*",
            "select (null::products).category",
            # Any other type the config doesn't list.
            "select '1'::order_status",
            "select 'a'::citext",
        ],
    )
    def test_a_cast_that_asks_the_catalog_is_refused(self, sql: str) -> None:
        _refused(POSTGRES, sql, C.TYPE_NOT_ALLOWED)

    @pytest.mark.parametrize(
        "sql",
        [
            "select '1'::int, cast('2' as numeric(10, 2)), '3'::text, 4::bigint",
            "select '2026-01-01'::date, now()::timestamptz, '1 day'::interval",
            "select '{}'::jsonb, '<a/>'::xml, array[1]::int[], 'x'::varchar(10)",
            "select 'a'::uuid, true::boolean, '10.0.0.1'::inet",
        ],
    )
    def test_standard_types_are_not(self, sql: str) -> None:
        assert _warden(POSTGRES)[0].check(sql).allowed

    def test_a_type_the_config_lists_is_allowed(self) -> None:
        shape = ShapeConfig(allowed_types=("Order_Status", "public.citext"))
        warden, _ = _warden(POSTGRES, shape)
        assert warden.check("select 'shipped'::order_status, 'a'::public.citext").allowed
        # As written: listing a name does not list it in every schema.
        assert _code(warden.check("select 'a'::citext")) == C.TYPE_NOT_ALLOWED
        assert _code(warden.check("select 'a'::other.order_status")) == C.TYPE_NOT_ALLOWED

    def test_the_reason_says_which_and_what_to_do(self) -> None:
        warden, _ = _warden(POSTGRES)
        refused = warden.check("select 'employee_salaries'::regclass").refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert (refused.check, refused.refusal.reason) == (
            "shape",
            "a cast to regclass is never allowed: it looks a name up in the database's "
            "catalog, where the checks can't follow",
        )
        refused = warden.check("select '1'::Order_Status").refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert refused.refusal.reason == (
            "order_status is not a standard SQL type sql-warden knows; a cast to it must be "
            "listed in shape.allowed_types"
        )

    @pytest.mark.parametrize("name", ["regclass", "pg_catalog.regrole", "REGPROC"])
    def test_no_config_can_allow_a_type_that_looks_names_up(self, name: str) -> None:
        with pytest.raises(ConfigError, match="a cast to it is never allowed"):
            parse_config(f"version: 1\nshape:\n  allowed_types: [{name}]\n")

    def test_snowflake_has_no_such_types(self) -> None:
        _refused(SNOWFLAKE, "select 1::employee_salaries", C.PARSE_ERROR)


class TestWhatTheProfileCantSee:
    @pytest.mark.parametrize(
        ("sql", "code"),
        _cases(
            (
                C.TABLE_NOT_ALLOWED,
                [
                    "select * from employee_salaries",
                    # Folded to the same name, or quoted as it is stored: the same table.
                    "select * from EMPLOYEE_SALARIES",
                    'select * from "employee_salaries"',
                    'select * from public."employee_salaries"',
                    "select * from only employee_salaries",
                    "select * from employee_salaries*",
                    # A Cyrillic letter: another name, and no such table.
                    "select * from employee_s\u0430laries",
                    "select * from pg_catalog.pg_shadow",
                    "select * from information_schema.tables",
                    "select * from pg_user",
                    # A CTE with an allowed table's name hides nothing inside it.
                    "with products as (select * from employee_salaries) select * from products",
                    "select * from products p, lateral (select * from employee_salaries) s",
                    "select (select max(salary_cents) from employee_salaries)",
                    "select 1 where exists (select 1 from employee_salaries)",
                    "select id from orders where id in (select id from employee_salaries)",
                    "select id from orders union all select salary_cents from employee_salaries",
                ],
            ),
            (
                C.COLUMN_NOT_ALLOWED,
                [
                    "select category from products",
                    "select 1 from products order by category",
                    "select 1 from products where category = 'Books'",
                    "select 1 from products group by category",
                    "select max(category) from products",
                    "select p.id from products p join orders o on o.note = p.category",
                    'select "a;b" from products',
                ],
            ),
            (
                C.STAR_NOT_ALLOWED,
                [
                    "select * from products",
                    "select p.* from products p",
                    # The row as one value: the columns left out come along.
                    "select p from products p",
                    "select products from products",
                    "select products::text from products",
                    "select (p).category from products p",
                    "select 1 from products p where p::text like '%x%'",
                    "select count(*) from products p group by p",
                ],
            ),
        ),
    )
    def test_postgres(self, sql: str, code: RefusalCode) -> None:
        _refused(POSTGRES, sql, code)

    @pytest.mark.parametrize(
        ("sql", "code"),
        _cases(
            (
                C.TABLE_NOT_ALLOWED,
                [
                    "select * from employee_salaries",
                    'select * from "PUBLIC"."EMPLOYEE_SALARIES"',
                    'select * from public."employee_salaries"',
                    # Another database's table, with an allowed one's name.
                    "select id from OTHERDB.PUBLIC.ORDERS",
                    "select * from snowflake.account_usage.query_history",
                    # Files in a stage are no table.
                    "select * from @stage",
                ],
            ),
            (
                C.COLUMN_NOT_ALLOWED,
                [
                    "select category from products",
                    # A column by its position, where its name can't be checked.
                    "select $1 from products",
                    "select t.$1 from products t",
                ],
            ),
            (
                C.STAR_NOT_ALLOWED,
                [
                    "select * from products",
                    "select products.* from products",
                    "select * exclude (id) from products",
                    # The table as it was a minute ago is still the table.
                    "select * from products at(offset => -60)",
                    "select * from products sample (10)",
                ],
            ),
        ),
    )
    def test_snowflake(self, sql: str, code: RefusalCode) -> None:
        _refused(SNOWFLAKE, sql, code)


class TestMaskedColumns:
    """ssn comes back hidden. So nothing may show it some other way: by what a filter lets
    through, by the order rows come in, by what is computed from it."""

    @pytest.mark.parametrize(
        ("sql", "code"),
        _cases(
            (
                C.MASKED_COLUMN_IN_PREDICATE,
                [
                    "select id from customers where ssn like '1%'",
                    "select id from customers where ssn is not null",
                    "select id from customers where id = 1 or ssn similar to '1%'",
                    "select id from customers where ssn = any(array['1'])",
                    "select id from customers where (id, ssn) in ((1, '123'))",
                    # Sorting and grouping, by name or by position.
                    "select id, ssn from customers order by 2",
                    "select id, ssn from customers order by 2 desc, 1",
                    "select ssn, count(*) from customers group by 1",
                    "select ssn from customers group by ssn",
                    "select 1 from customers group by rollup (ssn)",
                    "select 1 from customers group by grouping sets ((ssn), ())",
                    "select id from customers group by id having max(ssn) > '5'",
                    "select distinct ssn from customers",
                    "select distinct on (ssn) id from customers",
                    "select distinct on (1) ssn, id from customers",
                    "select id from customers order by (select ssn)",
                    # Joins that never write its name in a condition.
                    "select id from customers join (select '123-45-6789' as ssn) x using (ssn)",
                    "select c.id from customers c join customers d using (ssn)",
                    # The whole row is the masked column too.
                    "select id from customers c where c::text like '%123%'",
                    "select id from customers where customers::text like '%123%'",
                    "select id from customers c order by c",
                    "select id from customers c where (c).ssn = '1'",
                    # Renamed on the way through a subquery or a CTE.
                    "select id from (select id, ssn as x from customers) t where x like '1%'",
                    "with t as (select ssn x from customers) select count(*) from t group by x",
                    "with t as (select ssn x from customers) select x from t order by x",
                    "select id from customers c join lateral (select c.ssn as s) l on true "
                    "where l.s > '5'",
                    "select id from customers where id in "
                    "(select id from customers where ssn > '5')",
                    "select id from customers where exists (select 1 from customers d "
                    "where d.ssn = customers.ssn and d.id <> customers.id)",
                    "select id from customers offset "
                    "(select count(*) from customers where ssn > '5')",
                    # Set operations compare whole rows.
                    "select ssn from customers union select '123-45-6789'",
                    "select ssn from customers intersect select '123-45-6789'",
                    "select ssn from customers except select '123-45-6789'",
                    # Windows, named or not.
                    "select id from customers window w as (order by ssn)",
                    "select id, count(*) over w from customers window w as (partition by ssn)",
                    "select x.ssn from customers c, lateral (values (c.ssn)) x(ssn)",
                    "select v from customers c, unnest(array[c.ssn]) v",
                ],
            ),
            (
                C.MASKED_COLUMN_IN_EXPRESSION,
                [
                    "select upper(ssn) from customers",
                    "select ssn || '' from customers",
                    "select ssn::int from customers",
                    "select length(ssn) from customers",
                    "select coalesce(ssn, 'x') from customers",
                    "select nullif(ssn, '123-45-6789') from customers",
                    "select ssn is null from customers",
                    "select ssn between '1' and '2' from customers",
                    "select case when ssn like '1%' then 1 else 0 end from customers",
                    "select format('%s', ssn) from customers",
                    # One value out of many is still a value.
                    "select max(ssn) from customers",
                    "select min(ssn), max(ssn) from customers",
                    "select array_agg(ssn) from customers",
                    "select string_agg(ssn, ',') from customers",
                    "select json_agg(ssn) from customers",
                    "select count(*) filter (where ssn > '5') from customers",
                    "select sum(case when ssn > '5' then 1 end) from customers",
                    "select row_number() over (order by ssn), id from customers",
                    "select rank() over (partition by ssn order by id), id from customers",
                    "select id, lag(ssn) over (order by id) from customers",
                    "select id, first_value(ssn) over (order by id) from customers",
                    # A subquery in the select list is an expression.
                    "select (select ssn) from customers",
                    "select array(select ssn from customers)",
                    "select id, (select c2.ssn from customers c2 where c2.id = c.id) "
                    "from customers c",
                    "select (select array_agg(s) from (select ssn s from customers) q)",
                ],
            ),
        ),
    )
    def test_postgres(self, sql: str, code: RefusalCode) -> None:
        _refused(POSTGRES, sql, code)

    @pytest.mark.parametrize(
        ("sql", "code"),
        _cases(
            (
                C.MASKED_COLUMN_IN_PREDICATE,
                [
                    "select id from customers where ssn rlike '1.*'",
                    "select id from customers where contains(ssn, '1')",
                    "select * from customers qualify row_number() over (order by ssn) = 1",
                    "select id from customers qualify "
                    "row_number() over (partition by ssn order by id) = 1",
                    "select * from customers match_recognize "
                    "(partition by ssn pattern (a) define a as true)",
                    "select * from customers unpivot (v for k in (ssn, email))",
                    "select f.value from customers, lateral flatten(input => split(ssn, '-')) f",
                ],
            ),
            (
                C.MASKED_COLUMN_IN_EXPRESSION,
                [
                    "select iff(ssn like '1%', 1, 0) from customers",
                    "select decode(ssn, '1', 1) from customers",
                    "select customers.ssn:x from customers",
                    # Every column at once, as one value.
                    "select object_construct(*) from customers",
                    "select array_construct(*) from customers",
                    "select to_json(object_construct(*)) from customers",
                ],
            ),
        ),
    )
    def test_snowflake(self, sql: str, code: RefusalCode) -> None:
        _refused(SNOWFLAKE, sql, code)

    @pytest.mark.parametrize(
        ("dialect", "sql", "masked"),
        [
            # Another name doesn't take the mask off, and nor does swapping two.
            (POSTGRES, "select ssn as id from customers", {0: "redact"}),
            (POSTGRES, "select id as ssn, ssn as id from customers", {1: "redact"}),
            (POSTGRES, "select c.* from customers c", {2: "hmac", 4: "redact"}),
            (POSTGRES, "select * from (select * from customers) t", {2: "hmac", 4: "redact"}),
            (
                POSTGRES,
                "select t.* from (select ssn as a, ssn as b from customers) t",
                {0: "redact", 1: "redact"},
            ),
            # Snowflake's ways to pick, rename and swap what * returns.
            (SNOWFLAKE, "select * ilike '%a%' from customers", {1: "hmac"}),
            (SNOWFLAKE, "select * rename (ssn as x) from customers", {2: "hmac", 4: "redact"}),
            (
                SNOWFLAKE,
                "select * replace (ssn as id) from customers",
                {0: "redact", 2: "hmac", 4: "redact"},
            ),
        ],
    )
    def test_selected_some_other_way_it_is_still_masked(
        self, dialect: str, sql: str, masked: dict[int, str]
    ) -> None:
        decision = _warden(dialect)[0].check(sql)
        assert decision.allowed, decision.refused_by
        assert {output.position: output.strategy for output in decision.masked} == masked


class TestLimits:
    @pytest.mark.parametrize(
        "sql",
        [
            "select id from orders limit all",
            "select id from orders limit null",
            "select id from orders limit 1e9",
            "select id from orders limit 5 + 5",
            "select id from orders limit (select 1000000)",
            "select id from orders fetch first 100 percent rows only",
            "select id from orders fetch first 1 rows with ties",
        ],
    )
    def test_a_limit_that_cant_be_held_to_is_refused(self, sql: str) -> None:
        _refused(POSTGRES, sql, C.INVALID_LIMIT)

    @pytest.mark.parametrize(
        ("dialect", "sql", "runs"),
        [
            (
                POSTGRES,
                "select id from orders limit 1000000 offset 5",
                "SELECT id FROM public.orders LIMIT 101 OFFSET 5",
            ),
            (
                POSTGRES,
                "select 1 union all select id from orders limit 1000000",
                "SELECT 1 UNION ALL SELECT id FROM public.orders LIMIT 101",
            ),
            (
                POSTGRES,
                "(select id from orders limit 1000000) union all (select id from orders)",
                "(SELECT id FROM public.orders LIMIT 1000000) UNION ALL "
                "(SELECT id FROM public.orders) LIMIT 101",
            ),
            (
                SNOWFLAKE,
                "select top 1000000 id from orders",
                "SELECT ID FROM PUBLIC.ORDERS LIMIT 101",
            ),
            (
                SNOWFLAKE,
                "select id from orders fetch first 1000000 rows only",
                "SELECT ID FROM PUBLIC.ORDERS LIMIT 101",
            ),
        ],
    )
    def test_a_high_one_is_lowered_wherever_it_is_written(
        self, dialect: str, sql: str, runs: str
    ) -> None:
        assert _warden(dialect)[0].check(sql).sql == runs


class TestMalformed:
    @pytest.mark.parametrize(
        "sql",
        [
            "select 'abc",
            "select E'abc",
            'select "abc',
            "select $$abc",
            "select 1 /* abc",
            "select 'a' || 'b",
        ],
    )
    @pytest.mark.parametrize("dialect", [POSTGRES, SNOWFLAKE])
    def test_a_string_or_comment_that_never_ends(self, dialect: str, sql: str) -> None:
        warden, _ = _warden(dialect)
        refused = warden.check(sql).refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert (refused.check, refused.refusal.code, refused.refusal.reason) == (
            "parse",
            C.PARSE_ERROR,
            "the query ends inside a string, a quoted name or a comment: one of them is "
            "never closed",
        )

    @pytest.mark.parametrize(
        "sql",
        [
            "select 1\x00; drop table products",
            "select 'a\x00b'",
            "select '\ud800'",  # half a surrogate pair: not text, and JSON can carry one
        ],
    )
    @pytest.mark.parametrize("dialect", [POSTGRES, SNOWFLAKE])
    def test_what_is_not_text_is_refused_and_still_recorded(self, dialect: str, sql: str) -> None:
        _refused(dialect, sql, C.PARSE_ERROR)
        warden, _ = _warden(dialect)
        warden.check(sql)
        (event,) = warden.audit.events  # type: ignore[attr-defined]
        # As Postgres can store it: the audit log takes neither.
        assert "\x00" not in event.sql
        event.sql.encode("utf-8")
        assert event.sql in {
            "select 1\\x00; drop table products",
            "select 'a\\x00b'",
            "select '\\ud800'",
        }

    @pytest.mark.parametrize(
        "sql",
        [
            "sel\u200bect 1",  # a zero-width space inside the keyword
            "\ufeffselect 1",  # a byte order mark before it
            'select * from U&"employee\\005Fsalaries"',  # a name written in escapes
            "select employee_salaries '(1,x,1)'",
        ],
    )
    def test_characters_that_only_look_like_sql(self, sql: str) -> None:
        _refused(POSTGRES, sql, C.PARSE_ERROR)


def _deep(opening: str, closing: str, depth: int, inside: str = "1") -> str:
    return "select " + opening * depth + inside + closing * depth


class TestTooComplexToRead:
    """sqlglot's parser tries a reading and goes back when it was wrong. After a type's name
    it reads what is in the brackets twice, so each level doubles the work: 30 levels of
    date(date(...)) would keep it busy for hours. Such a query is turned away before the
    parser sees it."""

    @pytest.mark.parametrize("dialect", [POSTGRES, SNOWFLAKE])
    @pytest.mark.parametrize(
        "sql",
        [
            _deep("date(", ")", 30),
            _deep("array[", "]", 30),
            _deep("int[", "]", 30),
            _deep("varchar(", ")", 30),
            _deep("date((", "))", 30),  # other brackets in between don't help
            _deep("date(abs(", "))", 5),
            _deep("date(", ")", MAX_TYPE_NESTING + 1),
            _deep("(", ")", MAX_NESTING + 1),
            _deep("(", ")", 3000),
            _deep("abs(", ")", 200),
            _deep("[", "]", 500),
            "select * from " + "(select * from " * 500 + "orders" + ") x" * 500,
            # No brackets at all: the parser runs out of stack instead.
            "select " + "not " * 2000 + "true",
            "select " + "case when true then " * 300 + "1" + " end" * 300,
        ],
        ids=lambda sql: sql[:40],
    )
    def test_deep_nesting_is_refused_without_being_parsed(self, dialect: str, sql: str) -> None:
        with _work_limit(50_000):  # reading any of these properly would take millions
            _refused(dialect, sql, C.QUERY_TOO_COMPLEX)

    @pytest.mark.parametrize("dialect", [POSTGRES, SNOWFLAKE])
    def test_one_that_reads_but_is_too_deep_to_write_out_again(self, dialect: str) -> None:
        # No brackets, and the parser reads it in a loop; writing it back out is what
        # can't be done. Found before the other checks run, not after they have passed it.
        warden, _ = _warden(dialect)
        refused = warden.check("select 1" + "::int" * 2000).refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert (refused.check, refused.refusal.code) == ("parse", C.QUERY_TOO_COMPLEX)

    @pytest.mark.parametrize(
        "sql",
        [
            _deep("date(", ")", MAX_TYPE_NESTING),
            _deep("array[", "]", MAX_TYPE_NESTING, "1, 2"),
            _deep("(", ")", MAX_NESTING),
            "select coalesce(nullif(trim(lower(name)), ''), 'n/a') from products where id in "
            "(select id from orders where (quantity > 1 and (note is null or (id < 5))))",
        ],
        ids=lambda sql: sql[:40],
    )
    def test_what_a_real_query_nests_is_read(self, sql: str) -> None:
        assert _code(_warden(POSTGRES)[0].check(sql)) is None

    def test_the_reasons_say_what_the_limit_is(self) -> None:
        warden, _ = _warden(POSTGRES)

        def reason(sql: str) -> str:
            refused = warden.check(sql).refused_by
            assert refused is not None
            assert refused.refusal is not None
            assert refused.check == "parse"
            return refused.refusal.reason

        assert reason(_deep("(", ")", 40)) == (
            "brackets nest 40 deep in the query; at most 32 levels are read"
        )
        assert reason(_deep("array[", "]", 9)) == (
            "the query nests 9 type names with brackets, like date(date(...)) or "
            "array[array[...]]; at most 4 levels are read"
        )
        assert reason("select " + "not " * 2000 + "true") == (
            "the query nests too deeply to be read; simplify it"
        )

    @pytest.mark.parametrize("dialect", [POSTGRES, SNOWFLAKE])
    def test_a_query_too_long_is_not_read_and_recorded_cut_short(self, dialect: str) -> None:
        sql = "select 1 /*" + "x" * 5_000_000 + "*/"
        warden, _ = _warden(dialect)
        with _work_limit(50_000):
            refused = warden.run(sql).decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert (refused.refusal.code, refused.refusal.reason) == (
            C.QUERY_TOO_COMPLEX,
            "the query is 5,000,013 characters long; at most 20,000 are read",
        )
        (event,) = warden.audit.events  # type: ignore[attr-defined]
        assert event.sql == (
            sql[:RECORDED_OF_TOO_LONG] + "... (5,000,013 characters; the first 2,000 are recorded)"
        )

    def test_one_just_short_enough_is_read(self) -> None:
        sql = "select 1 /*" + "x" * (MAX_LENGTH - 13) + "*/"
        assert len(sql) == MAX_LENGTH
        warden, _ = _warden(POSTGRES)
        assert warden.check(sql).allowed
        (event,) = warden.audit.events  # type: ignore[attr-defined]
        assert event.sql == sql  # as sent

    @pytest.mark.parametrize("dialect", [POSTGRES, SNOWFLAKE])
    def test_no_keyword_makes_the_parser_work_like_that_unnoticed(self, dialect: str) -> None:
        """Every keyword of the dialect, nested 14 deep with each kind of bracket: either
        the query is turned away unread, or reading it is ordinary work. A keyword that
        doubles the work per level and isn't counted as a type's name would fail here, which
        is how a new sqlglot would show it has grown another."""
        warden, _ = _warden(dialect)
        keywords = sorted(
            {
                keyword.strip().lower()
                for keyword in Dialect.get_or_raise(dialect).tokenizer_class.KEYWORDS
                if keyword.replace("_", "").replace(" ", "").isalpha()
            }
        )
        assert len(keywords) > 200
        turned_away = 0
        for keyword in keywords:
            for opening, closing in (("(", ")"), ("[", "]")):
                sql = _deep(keyword + opening, closing, 14)
                try:
                    with _work_limit(250_000):
                        code = _code(warden.check(sql))
                except _TooMuchWork:
                    pytest.fail(f"reading {sql!r} takes the parser more than 250,000 calls")
                turned_away += code == C.QUERY_TOO_COMPLEX
        assert turned_away > 150  # the type names, each with both brackets


class _TooMuchWork(Exception):
    pass


@contextmanager
def _work_limit(calls: int) -> Iterator[None]:
    """Fail what runs inside if it makes more than this many Python calls: a measure of
    work that is the same on a fast machine and a slow one, which a time limit is not."""
    made = 0

    def count(frame: FrameType, event: str, arg: object) -> None:
        nonlocal made
        if event == "call":
            made += 1
            if made > calls:
                sys.setprofile(None)
                raise _TooMuchWork

    before = sys.getprofile()
    sys.setprofile(count)
    try:
        yield
    finally:
        sys.setprofile(before)


class TestDefused:
    """Allowed, because what runs is not what was sent: the query is written out again from
    what the checks read."""

    @pytest.mark.parametrize(
        ("sql", "runs"),
        [
            # Comments are dropped, whatever is in them.
            ("select 1 -- ; delete from products", "SELECT 1 LIMIT 101"),
            ("select 1 /* ; delete from products */", "SELECT 1 LIMIT 101"),
            ("select 1 /* /* nested */ ; delete from products */", "SELECT 1 LIMIT 101"),
            ("select 1 /*! union select ssn from customers */", "SELECT 1 LIMIT 101"),
            ("select 1 /* ' */ , 2 /* ' */", "SELECT 1, 2 LIMIT 101"),
            ("select 1;; ", "SELECT 1 LIMIT 101"),
            # Space that isn't a space to Postgres becomes one.
            ("select\u00a01", "SELECT 1 LIMIT 101"),
            ("select\x0b1,\x0c2", "SELECT 1, 2 LIMIT 101"),
            # A string stays one string, written the plain way.
            ("select $x$;$x$", "SELECT ';' LIMIT 101"),
            ("select $a$ ' $a$", "SELECT ' '' ' LIMIT 101"),
            ("select $$ $a$ $$", "SELECT ' $a$ ' LIMIT 101"),
            ("select ' /* ' , ' */ '", "SELECT ' /* ', ' */ ' LIMIT 101"),
            ("select '--' , 1", "SELECT '--', 1 LIMIT 101"),
            (
                r"select E'a\'; drop table products; --'",
                "SELECT e'a''; drop table products; --' LIMIT 101",
            ),
            (
                r"select E'\x27; drop table products; --'",
                "SELECT e'''; drop table products; --' LIMIT 101",
            ),
            (
                r"select E'\047; drop table products; --'",
                "SELECT e'''; drop table products; --' LIMIT 101",
            ),
            (
                'select 1 as "x"";delete from products;--"',
                'SELECT 1 AS "x"";delete from products;--" LIMIT 101',
            ),
            # A CTE named like a table reads what it says, and only that.
            (
                "with products as (select id from orders) select * from products",
                "WITH products AS (SELECT id FROM public.orders) SELECT * FROM products LIMIT 101",
            ),
        ],
    )
    def test_postgres(self, sql: str, runs: str) -> None:
        assert _warden(POSTGRES)[0].check(sql).sql == runs

    @pytest.mark.parametrize(
        ("sql", "runs"),
        [
            ("select 1 /* ; delete */", "SELECT 1 LIMIT 101"),
            ("select $$ ; delete from products $$", "SELECT ' ; delete from products ' LIMIT 101"),
            # In Snowflake a backslash does escape the quote: one string, here and there.
            (
                r"select 'a\'; delete from products; --'",
                r"SELECT 'a\'; delete from products; --' LIMIT 101",
            ),
            (
                r"select '\x27; delete from products; --'",
                r"SELECT '\'; delete from products; --' LIMIT 101",
            ),
            (
                r"select 'a\\', '; delete from products; --'",
                r"SELECT 'a\\', '; delete from products; --' LIMIT 101",
            ),
            (
                'select 1 as "a""; delete from products; --"',
                'SELECT 1 AS "a""; delete from products; --" LIMIT 101',
            ),
        ],
    )
    def test_snowflake(self, sql: str, runs: str) -> None:
        assert _warden(SNOWFLAKE)[0].check(sql).sql == runs


def _everything_allowed() -> list[tuple[str, str]]:
    """Each query this file expects to be allowed, with its dialect."""
    allowed: list[tuple[str, str]] = []
    for dialect, test in (
        (POSTGRES, TestDefused.test_postgres),
        (SNOWFLAKE, TestDefused.test_snowflake),
    ):
        (mark,) = test.pytestmark  # type: ignore[attr-defined]
        allowed += [(dialect, case[0]) for case in mark.args[1]]
    return allowed


@pytest.mark.parametrize(("dialect", "sql"), _everything_allowed())
def test_whatever_is_allowed_runs_as_one_plain_select(dialect: str, sql: str) -> None:
    """Read back, the query that would run is one statement, a SELECT, with no comment, no
    write and no lock in it."""
    runs = _warden(dialect)[0].check(sql).sql
    assert runs is not None
    (statement,) = sqlglot.parse(runs, dialect=dialect)
    assert isinstance(statement, exp.Query)
    assert statement.find(exp.DML, exp.Into, exp.Lock, exp.Command) is None
    assert not any(node.comments for node in statement.walk())
    assert statement.sql(dialect=dialect) == runs  # written out again, it doesn't change
