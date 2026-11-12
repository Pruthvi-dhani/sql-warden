"""The checks reading Snowflake SQL: what only Snowflake has, and its ways of reading
something without naming it.

The shape, access, lineage and masking tests run under both dialects (tests/unit/dialects.py);
this is what they can't share.
"""

from typing import Any

import pytest

from sql_warden.audit import MemoryAuditSink
from sql_warden.config import (
    BUILTIN_DENIED_FUNCTIONS,
    ConfigError,
    MaskRule,
    ShapeConfig,
    parse_config,
)
from sql_warden.engines import Column, Result, Table
from sql_warden.models import Decision
from sql_warden.profiles import Access
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine


def _table(schema: str, name: str, *columns: str) -> Table:
    return Table(schema, name, tuple(Column(column, "TEXT") for column in columns))


# As Snowflake stores them: upper case, unless created with a quoted name.
CATALOG = (
    _table("PUBLIC", "CUSTOMERS", "ID", "EMAIL", "SSN", "TAGS"),
    _table("PUBLIC", "PRODUCTS", "ID", "NAME", "CATEGORY"),
    _table("PUBLIC", "SECRETS", "ID", "V"),
    _table("PUBLIC", "MixedCase", "Id"),
    _table("ANALYTICS", "DAILY", "DAY", "TOTAL"),
)
SUPPORT = Access(
    {
        ("PUBLIC", "CUSTOMERS"): "*",
        ("PUBLIC", "PRODUCTS"): frozenset({"ID", "NAME"}),
        ("PUBLIC", "MixedCase"): "*",
    }
)
MASKS = {
    ("PUBLIC", "CUSTOMERS", "SSN"): MaskRule.model_validate("redact"),
    ("PUBLIC", "CUSTOMERS", "TAGS"): MaskRule.model_validate("redact"),
}
REFUSED = tuple[str, str, str]


def _warden(
    *,
    access: Access | None = SUPPORT,
    masks: bool = False,
    engine: FakeEngine | None = None,
    **settings: Any,
) -> Warden:
    return Warden(
        engine or FakeEngine(catalog=CATALOG),
        audit=MemoryAuditSink(),
        dialect="snowflake",
        profile="support" if access else "all",
        access=access,
        masks=MASKS if masks else None,
        **settings,
    )


def _refusal(decision: Decision) -> REFUSED:
    refused = decision.refused_by
    assert refused is not None, f"allowed: {decision.sql}"
    assert refused.refusal is not None
    return refused.check, refused.refusal.code, refused.refusal.reason


def _refused(sql: str, **settings: Any) -> REFUSED:
    return _refusal(_warden(**settings).check(sql))


def _runs(sql: str, **settings: Any) -> str:
    decision = _warden(**settings).check(sql)
    assert decision.allowed, decision.refused_by
    assert decision.sql is not None
    return decision.sql


class TestNames:
    """Snowflake stores an unquoted name in upper case, and looks one up the same way."""

    @pytest.mark.parametrize(
        "sql",
        [
            "select id, email from customers",
            "select ID, Email from Customers",
            'select "ID" from "CUSTOMERS"',
        ],
    )
    def test_unquoted_names_are_upper_case(self, sql: str) -> None:
        assert "FROM PUBLIC" in _runs(sql)

    def test_what_runs_names_the_schema(self) -> None:
        assert _runs("select id from customers") == "SELECT ID FROM PUBLIC.CUSTOMERS LIMIT 101"

    def test_a_quoted_lower_case_name_is_another_name(self) -> None:
        assert _refused('select "id" from customers')[1:] == (
            "COLUMN_NOT_ALLOWED",
            "column id is not available to profile support",
        )

    def test_a_name_created_quoted_keeps_its_case(self) -> None:
        assert (
            _runs('select "Id" from "MixedCase"') == 'SELECT "Id" FROM PUBLIC."MixedCase" LIMIT 101'
        )
        assert _refused("select id from mixedcase")[1:] == (
            "TABLE_NOT_ALLOWED",
            "table PUBLIC.MIXEDCASE is not available to profile support",
        )

    def test_a_database_cant_be_named(self) -> None:
        assert _refused("select * from other_db.public.customers")[1] == "TABLE_NOT_ALLOWED"

    def test_the_default_schema_can_be_another(self) -> None:
        # The connection's schema, which the Snowflake engine will pass on.
        warden = _warden(access=Access("*"), default_schema="ANALYTICS")
        assert warden.check("select day from daily").sql == (
            "SELECT DAY FROM ANALYTICS.DAILY LIMIT 101"
        )
        assert _refusal(warden.check("select id from customers"))[1] == "TABLE_NOT_ALLOWED"
        table = warden.table("daily")
        assert table is not None
        assert (table.schema, table.name) == ("ANALYTICS", "DAILY")

    def test_tables_are_found_by_name_as_sql_reads_it(self) -> None:
        warden = _warden()
        products = warden.table("products")
        assert products is not None
        assert [column.name for column in products.columns] == ["ID", "NAME"]
        assert warden.table('"MixedCase"') is not None
        assert warden.table("mixedcase") is None
        assert warden.table("secrets") is None


class TestTop:
    """TOP n is Snowflake's other way to write LIMIT n; what runs says LIMIT."""

    def test_within_the_cap_it_is_kept(self) -> None:
        decision = _warden().check("select top 5 id from customers order by id")
        assert decision.sql == "SELECT ID FROM PUBLIC.CUSTOMERS ORDER BY ID LIMIT 5"
        assert decision.rewrites == ()

    def test_above_the_cap_it_is_lowered(self) -> None:
        decision = _warden().check("select top 5000 id from customers")
        assert decision.sql == "SELECT ID FROM PUBLIC.CUSTOMERS LIMIT 101"
        assert decision.rewrites == (
            "lowered LIMIT 5000 to 101 (row cap 100 + 1 to detect truncation)",
        )

    def test_it_counts_as_a_limit_where_one_is_required(self) -> None:
        require = ShapeConfig(limit="require")
        assert _warden(shape=require).check("select top 100 id from customers").allowed
        assert _refused("select top 101 id from customers", shape=require)[1] == "LIMIT_TOO_HIGH"
        assert _refused("select id from customers", shape=require)[1] == "LIMIT_REQUIRED"

    def test_a_query_without_either_gets_a_limit(self) -> None:
        assert _runs("select id from customers").endswith("LIMIT 101")


class TestNamedOutright:
    """Everything a query reads must be named in its text, where the checks can see it."""

    @pytest.mark.parametrize(
        ("sql", "code", "reason"),
        [
            (
                "select * from identifier('secrets')",
                "FUNCTION_NOT_ALLOWED",
                "identifier() is never allowed: it names a table or column with a string or a "
                "variable, which can't be checked; write the name itself",
            ),
            ("select * from identifier($t)", "FUNCTION_NOT_ALLOWED", "identifier() is never"),
            ("select identifier('ssn') from customers", "FUNCTION_NOT_ALLOWED", "identifier()"),
            (
                "select * from table('secrets')",
                "FUNCTION_NOT_ALLOWED",
                "TABLE('secrets') names a table with a string or a variable, which can't be "
                "checked; write the table's name itself",
            ),
            ("select * from table($t)", "FUNCTION_NOT_ALLOWED", "TABLE($t) names a table"),
            (
                "select $1 from @my_stage/file.csv",
                "TABLE_NOT_ALLOWED",
                "@my_stage/file.csv is not a table: files in stages can't be queried",
            ),
            ("select * from @%customers", "TABLE_NOT_ALLOWED", "@%customers is not a table"),
            ("select * from @~/mine.csv", "TABLE_NOT_ALLOWED", "@~/mine.csv is not a table"),
            ("select * from '@my_stage/f'", "TABLE_NOT_ALLOWED", "'@my_stage/f' is not a table"),
            (
                # products' third column is one this profile may not read.
                "select $3 from products",
                "COLUMN_NOT_ALLOWED",
                "$3 is a column given by its position, or a session variable; neither can be "
                "checked, so name the column or write the value",
            ),
            ("select p.$3 from products p", "COLUMN_NOT_ALLOWED", "$3 is a column given by"),
            ("select id from products where name = $who", "COLUMN_NOT_ALLOWED", "$who is a"),
            ("select $1 from (values (1), (2))", "COLUMN_NOT_ALLOWED", "$1 is a column"),
        ],
    )
    @pytest.mark.parametrize("access", [SUPPORT, None], ids=["support", "no-rules"])
    def test_a_name_given_any_other_way_is_refused(
        self, sql: str, code: str, reason: str, access: Access | None
    ) -> None:
        # By the shape check, so with no access rules at all it is refused just the same.
        check, refused_code, refused_reason = _refused(sql, access=access)
        assert (check, refused_code) == ("shape", code)
        assert reason in refused_reason

    def test_values_with_named_columns_are_fine(self) -> None:
        assert _warden().check("select a from (values (1), (2)) as v(a)").allowed


class TestFunctions:
    @pytest.mark.parametrize(
        ("sql", "function"),
        [
            ("select system$wait(60)", "system$wait"),
            ("select SYSTEM$CANCEL_ALL_QUERIES(1)", "system$cancel_all_queries"),
            ("select * from table(result_scan(last_query_id()))", "result_scan"),
            ("select last_query_id()", "last_query_id"),
            ("select get_ddl('table', 'secrets')", "get_ddl"),
            ("select * from table(information_schema.query_history())", "query_history"),
            ("select * from table(information_schema.query_history_by_user())", "query_history"),
            ("select build_scoped_file_url('x', 'f.csv')", "build_scoped_file_url"),
        ],
    )
    def test_the_ones_never_allowed(self, sql: str, function: str) -> None:
        check, code, reason = _refused(sql)
        assert (check, code) == ("shape", "FUNCTION_NOT_ALLOWED")
        assert reason.startswith(f"{function}") or f"{function}" in reason
        assert "is never allowed" in reason

    @pytest.mark.parametrize("name", ["system$wait", "result_scan", "get_ddl", "pg_sleep"])
    def test_no_config_can_allow_one_of_either_dialects(self, name: str) -> None:
        with pytest.raises(ConfigError, match="allowed_functions lists"):
            parse_config(f"version: 1\nshape:\n  allowed_functions: ['{name}']\n")

    def test_each_dialect_has_its_own_list(self) -> None:
        assert set(BUILTIN_DENIED_FUNCTIONS) == {"postgres", "snowflake"}
        shape = ShapeConfig()
        assert shape.denied_by("system$wait", "snowflake") == "system$*"
        assert shape.denied_by("system$wait", "postgres") is None
        assert shape.denied_by("pg_sleep", "postgres") == "pg_sleep*"
        assert shape.denied_by("pg_sleep", "snowflake") is None
        # Unknown to the other dialect, each is still refused there as an unknown function.
        assert "not a standard SQL function" in _refused("select pg_sleep(1)")[2]

    def test_functions_snowflake_has_are_known(self) -> None:
        sql = (
            "select iff(id > 1, 'a', 'b'), nvl(name, 'x'), to_varchar(id), try_to_number(name), "
            "dateadd(day, 1, current_date()), name ilike 'a%', id::varchar from products"
        )
        assert _warden().check(sql).allowed

    def test_a_table_function_is_held_to_the_same_rules(self) -> None:
        assert (
            "my_udtf() is not a standard SQL function"
            in _refused("select * from table(my_udtf(1))")[2]
        )
        allowed = ShapeConfig(allowed_functions=("my_udtf",))
        assert _warden(shape=allowed).check("select * from table(my_udtf(1))").allowed


class TestNotAQuery:
    @pytest.mark.parametrize(
        ("sql", "name"),
        [
            ("show tables", "SHOW"),
            ("describe table customers", "DESCRIBE"),
            ("use role accountadmin", "USE"),
            ("alter session set query_tag = 'x'", "ALTER"),
            ("set t = 'secrets'", "SET"),
            ("call my_procedure()", "CALL"),
            ("execute immediate 'select * from secrets'", "EXECUTE"),
            ("copy into @my_stage from customers", "COPY"),
            ("put file:///tmp/x @my_stage", "PUT"),
            ("insert into customers select * from customers", "INSERT"),
            ("create table x as select * from customers", "CREATE"),
        ],
    )
    def test_statements_that_arent_a_select(self, sql: str, name: str) -> None:
        assert _refused(sql) == (
            "shape",
            "NOT_A_SELECT",
            f"only SELECT queries are allowed, not {name}",
        )

    def test_one_statement_at_a_time(self) -> None:
        assert _refused("set t = 'x'; select * from identifier($t)")[1] == "MULTIPLE_STATEMENTS"

    @pytest.mark.parametrize(
        ("sql", "reason"),
        [
            ("select id from customers for update", "FOR UPDATE locks rows"),
            ("select my_sequence.nextval", "my_sequence.nextval advances a sequence"),
            ("select s.NEXTVAL from customers", "s.NEXTVAL advances a sequence"),
        ],
    )
    def test_selects_that_do_more_than_read(self, sql: str, reason: str) -> None:
        check, code, refused_reason = _refused(sql, access=None)
        assert (check, code) == ("shape", "NOT_READ_ONLY")
        assert reason in refused_reason

    def test_a_column_that_is_only_called_nextval_is_a_column(self) -> None:
        decision = _warden(access=None).check('select "NEXTVAL" from counters')
        assert decision.allowed


class TestAccess:
    @pytest.mark.parametrize(
        "sql",
        [
            "select f.value from products p, lateral flatten(input => p.name) f",
            "select f.value from products p, table(flatten(input => p.name)) f",
            "select name:a.b::string from products",
            "select id from products qualify row_number() over (partition by name order by id) = 1",
            "select id from products sample (10)",
            "select id, name from products at(offset => -60)",
            "select name, count(*) from products group by all",
            "select * exclude (ssn) from customers",
            "select * rename (ssn as s) from customers",
            "select object_construct(*) from customers",
            "select count(*) from products",
            "select id from products where name ilike any ('a%', 'b%')",
            "select id from products start with id = 1 connect by prior id = id",
        ],
    )
    def test_snowflake_syntax_over_what_the_profile_may_read(self, sql: str) -> None:
        assert _warden().check(sql).allowed

    @pytest.mark.parametrize(
        ("sql", "code"),
        [
            (
                "select f.value from products p, lateral flatten(input => p.category) f",
                "COLUMN_NOT_ALLOWED",
            ),
            ("select category:a from products", "COLUMN_NOT_ALLOWED"),
            (
                "select id from products qualify row_number() over (partition by category "
                "order by id) = 1",
                "COLUMN_NOT_ALLOWED",
            ),
            (
                "select id from products start with category = 'x' connect by prior id = id",
                "COLUMN_NOT_ALLOWED",
            ),
            ("select id from products unpivot (v for c in (name, category))", "COLUMN_NOT_ALLOWED"),
            (
                "select id from products match_recognize (pattern (a+) define a as category = 'x')",
                "COLUMN_NOT_ALLOWED",
            ),
            # Every column, however the star is dressed.
            ("select * exclude (category) from products", "STAR_NOT_ALLOWED"),
            ("select * ilike '%a%' from products", "STAR_NOT_ALLOWED"),
            ("select object_construct(*) from products", "STAR_NOT_ALLOWED"),
            (
                "select * from products pivot (count(id) for category in ('a', 'b'))",
                "STAR_NOT_ALLOWED",
            ),
            ("select * from secrets at(offset => -60)", "TABLE_NOT_ALLOWED"),
            ("select id from products, lateral (select v from secrets) s", "TABLE_NOT_ALLOWED"),
            ("select * from information_schema.tables", "TABLE_NOT_ALLOWED"),
        ],
    )
    def test_and_over_what_it_may_not(self, sql: str, code: str) -> None:
        check, refused_code, _ = _refused(sql)
        assert (check, refused_code) == ("access", code)


class TestMasking:
    def test_masks_follow_a_star_with_columns_left_out_or_renamed(self) -> None:
        def masked(sql: str) -> list[str]:
            decision = _warden(masks=True).check(sql)
            assert decision.allowed, decision.refused_by
            return [output.column for output in decision.masked]

        assert masked("select * from customers") == ["SSN", "TAGS"]
        assert masked("select * exclude (ssn, tags) from customers") == []
        assert masked("select * exclude (email) from customers") == ["SSN", "TAGS"]
        assert masked("select * rename (ssn as s) from customers") == ["S", "TAGS"]
        assert masked("select * from customers at(offset => -60)") == ["SSN", "TAGS"]

    @pytest.mark.parametrize(
        ("sql", "code"),
        [
            (
                "select f.value from customers c, lateral flatten(input => c.tags) f",
                "MASKED_COLUMN_IN_PREDICATE",
            ),
            (
                "select f.value from customers c, table(flatten(input => c.tags)) f",
                "MASKED_COLUMN_IN_PREDICATE",
            ),
            ("select tags:a.b::string from customers", "MASKED_COLUMN_IN_EXPRESSION"),
            (
                "select id from customers qualify row_number() over (partition by ssn "
                "order by id) = 1",
                "MASKED_COLUMN_IN_PREDICATE",
            ),
            ("select * replace (upper(ssn) as ssn) from customers", "MASKED_COLUMN_IN_EXPRESSION"),
            ("select object_construct(*) from customers", "MASKED_COLUMN_IN_EXPRESSION"),
            ("select array_agg(ssn) from customers", "MASKED_COLUMN_IN_EXPRESSION"),
            (
                "select id from customers start with ssn = '1' connect by prior id = id",
                "MASKED_COLUMN_IN_PREDICATE",
            ),
            (
                "select id from customers where ssn ilike any ('1%', '2%')",
                "MASKED_COLUMN_IN_PREDICATE",
            ),
            (
                "select * from customers pivot (count(id) for email in ('a', 'b'))",
                "MASKED_COLUMN_IN_EXPRESSION",
            ),
        ],
    )
    def test_uses_that_would_leak_are_refused(self, sql: str, code: str) -> None:
        check, refused_code, _ = _refused(sql, masks=True)
        assert (check, refused_code) == ("masking", code)

    def test_counting_is_still_fine(self) -> None:
        assert (
            _warden(masks=True)
            .check("select count(ssn), count(distinct ssn) from customers")
            .allowed
        )

    def test_rows_come_back_masked_by_position(self) -> None:
        rows = Result(
            columns=("ID", "S", "EMAIL"),
            rows=((1, "123-45-6789", "a@example.com"),),
            truncated=False,
            duration_ms=1.0,
        )
        engine = FakeEngine(catalog=CATALOG, result=rows)
        outcome = _warden(masks=True, engine=engine).run(
            "select id, ssn as s, email from customers"
        )
        assert outcome.result is not None
        assert outcome.result.rows == ((1, "[REDACTED]", "a@example.com"),)
        assert engine.executed == ["SELECT ID, SSN AS S, EMAIL FROM PUBLIC.CUSTOMERS LIMIT 101"]


class TestDialects:
    def test_a_dialect_the_checks_dont_read_is_an_error(self) -> None:
        with pytest.raises(ValueError, match="unknown SQL dialect 'mysql'"):
            Warden(FakeEngine(), audit=MemoryAuditSink(), dialect="mysql")

    def test_the_configs_engine_is_the_dialect(self) -> None:
        config = parse_config(
            "version: 1\nwarehouse:\n  engine: snowflake\n"
            "  dsn: snowflake://reader:pw@myorg-acct/warehouse/public\n"
        )
        assert config.warehouse.dialect == "snowflake"
        assert parse_config("version: 1").warehouse.dialect == "postgres"

    def test_comments_never_reach_the_warehouse(self) -> None:
        sql = "select id from customers -- ; drop table customers\n/* identifier('x') */"
        assert _runs(sql) == "SELECT ID FROM PUBLIC.CUSTOMERS LIMIT 101"
