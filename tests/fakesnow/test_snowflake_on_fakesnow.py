"""End to end through the Warden on a fake Snowflake: the engine, the catalog, and what the
checks regenerate, run as Snowflake SQL."""

from pathlib import Path

import pytest

from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import build_warden
from sql_warden.config import BudgetConfig, MaskRule, load_config
from sql_warden.engines import QueryFailed
from sql_warden.engines.snowflake import SnowflakeEngine
from sql_warden.models import Decision, QueryOutcome
from sql_warden.profiles import Access
from sql_warden.warden import Warden

MASK_KEY = b"a-key-for-these-tests-only"
SUPPORT = Access(
    {
        ("PUBLIC", "CUSTOMERS"): "*",
        ("PUBLIC", "ORDERS"): "*",
        ("PUBLIC", "PRODUCTS"): frozenset({"ID", "NAME", "PRICE_CENTS"}),
    }
)
MASKS = {
    ("PUBLIC", "CUSTOMERS", "SSN"): MaskRule.model_validate("redact"),
    ("PUBLIC", "CUSTOMERS", "PHONE"): MaskRule.model_validate("partial"),
    ("PUBLIC", "CUSTOMERS", "EMAIL"): MaskRule.model_validate("hmac"),
}


def _warden(dsn: str, *, max_rows: int = 100, masks: bool = False, **settings: object) -> Warden:
    engine = SnowflakeEngine(dsn, max_rows=max_rows)
    return Warden(
        engine,
        audit=MemoryAuditSink(),
        dialect="snowflake",
        default_schema=engine.default_schema,
        profile="support",
        access=SUPPORT,
        masks=MASKS if masks else None,
        mask_key=MASK_KEY if masks else None,
        **settings,  # type: ignore[arg-type]
    )


def _rows(outcome: QueryOutcome) -> tuple[tuple[object, ...], ...]:
    assert outcome.result is not None, outcome.decision.refused_by or outcome.error
    return outcome.result.rows


def _code(decision: Decision) -> str | None:
    refused = decision.refused_by
    return str(refused.refusal.code) if refused and refused.refusal else None


class TestTheEngine:
    def test_the_catalog_as_snowflake_stores_it(self, warehouse: str) -> None:
        tables = {table.name: table for table in SnowflakeEngine(warehouse).tables()}
        assert set(tables) == {"CUSTOMERS", "PRODUCTS", "ORDERS", "EMPLOYEE_SALARIES", "MixedCase"}
        assert {table.schema for table in tables.values()} == {"PUBLIC"}
        assert [column.name for column in tables["CUSTOMERS"].columns] == [
            "ID",
            "FULL_NAME",
            "EMAIL",
            "PHONE",
            "SSN",
        ]
        assert [column.name for column in tables["MixedCase"].columns] == ["Id", "LOW"]

    def test_rows_columns_and_the_row_cap(self, warehouse: str) -> None:
        result = SnowflakeEngine(warehouse, max_rows=3).execute(
            "SELECT ID, NAME FROM PUBLIC.PRODUCTS ORDER BY ID", tag="sql-warden test"
        )
        assert result.columns == ("ID", "NAME")
        assert result.rows == ((1, "Product 1"), (2, "Product 2"), (3, "Product 3"))
        assert result.truncated is True

    def test_a_query_snowflake_rejects(self, warehouse: str) -> None:
        with pytest.raises(QueryFailed) as excinfo:
            SnowflakeEngine(warehouse).execute("SELECT * FROM NOSUCH")
        assert excinfo.value.sqlstate == "42S02"


class TestThroughTheWarden:
    def test_what_the_checks_regenerate_runs(self, warehouse: str) -> None:
        outcome = _warden(warehouse).run("select id, name from products where id <= 3 order by id")
        assert outcome.decision.sql == (
            "SELECT ID, NAME FROM PUBLIC.PRODUCTS WHERE ID <= 3 ORDER BY ID LIMIT 101"
        )
        assert _rows(outcome) == ((1, "Product 1"), (2, "Product 2"), (3, "Product 3"))

    def test_the_added_limit_and_truncation(self, warehouse: str) -> None:
        outcome = _warden(warehouse, max_rows=5).run("select id from orders order by id")
        assert outcome.decision.sql == "SELECT ID FROM PUBLIC.ORDERS ORDER BY ID LIMIT 6"
        assert outcome.result is not None
        assert (len(outcome.result.rows), outcome.result.truncated) == (5, True)

    def test_top_is_capped_like_a_limit(self, warehouse: str) -> None:
        outcome = _warden(warehouse, max_rows=5).run("select top 5000 id from orders order by id")
        assert outcome.decision.sql == "SELECT ID FROM PUBLIC.ORDERS ORDER BY ID LIMIT 6"
        assert len(_rows(outcome)) == 5

    def test_a_join_and_an_aggregate(self, warehouse: str) -> None:
        outcome = _warden(warehouse).run(
            "select p.name, sum(o.quantity) as sold from orders o "
            "join products p on p.id = o.product_id group by p.name order by sold desc, p.name"
        )
        rows = _rows(outcome)
        assert len(rows) == 8
        assert sum(float(str(sold)) for _, sold in rows) == sum(n % 5 + 1 for n in range(1, 41))

    def test_names_keep_their_case_when_quoted(self, warehouse: str) -> None:
        engine = SnowflakeEngine(warehouse)
        warden = Warden(
            engine,
            audit=MemoryAuditSink(),
            dialect="snowflake",
            default_schema=engine.default_schema,
            profile="admin",
            access=Access("*"),
        )
        assert _rows(warden.run('select "Id", low from "MixedCase"')) == ((1, "a"),)
        assert _code(warden.run("select id from mixedcase").decision) == "TABLE_NOT_ALLOWED"

    @pytest.mark.parametrize(
        ("sql", "code"),
        [
            ("select * from employee_salaries", "TABLE_NOT_ALLOWED"),
            ("select category from products", "COLUMN_NOT_ALLOWED"),
            ("select * from products", "STAR_NOT_ALLOWED"),
            ("select $3 from products", "COLUMN_NOT_ALLOWED"),
            ("select * from identifier('employee_salaries')", "FUNCTION_NOT_ALLOWED"),
            ("select object_construct(*) from products", "STAR_NOT_ALLOWED"),
            ("delete from orders", "NOT_A_SELECT"),
        ],
    )
    def test_refusals_never_reach_snowflake(self, warehouse: str, sql: str, code: str) -> None:
        outcome = _warden(warehouse).run(sql)
        assert _code(outcome.decision) == code
        assert outcome.result is None

    @pytest.mark.parametrize(
        ("sql", "rows"),
        [
            (
                "select id from orders qualify row_number() over "
                "(partition by customer_id order by id) = 1 order by id",
                12,
            ),
            ("select id from customers where full_name ilike 'customer 1%'", 4),
            ("select iff(quantity > 2, 'big', 'small') as size, id::varchar from orders", 40),
            ("select o.id, f.value from orders o, lateral flatten(input => o.tags) f", 80),
        ],
    )
    def test_snowflake_syntax_runs(self, warehouse: str, sql: str, rows: int) -> None:
        assert len(_rows(_warden(warehouse).run(sql))) == rows


class TestMasking:
    def test_rows_come_back_masked(self, warehouse: str) -> None:
        outcome = _warden(warehouse, masks=True).run(
            "select id, full_name, email, phone, ssn from customers order by id limit 2"
        )
        first, second = _rows(outcome)
        assert first[:2] == (1, "Customer 1")
        assert isinstance(first[2], str)
        assert len(first[2]) == 16  # an hmac token
        assert "@" not in first[2]
        assert first[2] != second[2]
        assert (first[3], first[4]) == ("*******0001", "[REDACTED]")
        assert [masked.column for masked in outcome.decision.masked] == ["EMAIL", "PHONE", "SSN"]

    def test_a_star_is_masked_by_position(self, warehouse: str) -> None:
        clear = _rows(_warden(warehouse).run("select * from customers order by id limit 3"))
        masked = _rows(
            _warden(warehouse, masks=True).run("select * from customers order by id limit 3")
        )
        for seen, hidden in zip(clear, masked, strict=True):
            assert hidden[:2] == seen[:2]
            assert hidden[4] == "[REDACTED]"
            assert seen[4] not in hidden
            assert seen[2] not in hidden

    def test_the_same_value_gets_the_same_token(self, warehouse: str) -> None:
        warden = _warden(warehouse, masks=True)
        one = _rows(warden.run("select email from customers where id = 7"))
        again = _rows(
            warden.run(
                "select c.email from orders o join customers c on c.id = o.customer_id "
                "where c.id = 7 limit 1"
            )
        )
        assert one == again

    def test_columns_left_out_of_a_star_arent_masked_or_returned(self, warehouse: str) -> None:
        outcome = _warden(warehouse, masks=True).run(
            "select * exclude (email, phone, ssn) from customers order by id limit 1"
        )
        assert _rows(outcome) == ((1, "Customer 1"),)
        assert outcome.decision.masked == ()

    @pytest.mark.parametrize(
        ("sql", "code"),
        [
            ("select id from customers where ssn like '101%'", "MASKED_COLUMN_IN_PREDICATE"),
            ("select upper(email) from customers", "MASKED_COLUMN_IN_EXPRESSION"),
            ("select object_construct(*) from customers", "MASKED_COLUMN_IN_EXPRESSION"),
        ],
    )
    def test_uses_that_would_leak_are_refused(self, warehouse: str, sql: str, code: str) -> None:
        assert _code(_warden(warehouse, masks=True).run(sql).decision) == code

    def test_counting_a_masked_column(self, warehouse: str) -> None:
        outcome = _warden(warehouse, masks=True).run("select count(distinct ssn) from customers")
        assert _rows(outcome) == ((12,),)


class TestAuditAndBudgets:
    def test_every_request_is_recorded_with_what_ran(self, warehouse: str) -> None:
        warden = _warden(warehouse, masks=True)
        ran = warden.run("select id, ssn from customers order by id limit 4")
        warden.run("select * from employee_salaries")
        assert isinstance(warden.audit, MemoryAuditSink)
        allowed, refused = warden.audit.events
        assert allowed.id == ran.decision.audit_id
        assert (allowed.decision, allowed.rows_returned, allowed.masked_columns) == (
            "allowed",
            4,
            ("SSN",),
        )
        assert allowed.executed_sql == "SELECT ID, SSN FROM PUBLIC.CUSTOMERS ORDER BY ID LIMIT 4"
        assert allowed.cost_estimate == 50331648  # the saved plan's bytes
        assert (refused.decision, refused.code) == ("refused", "TABLE_NOT_ALLOWED")

    def test_a_session_budget_counts_real_rows(self, warehouse: str) -> None:
        warden = _warden(warehouse, max_rows=10, budget=BudgetConfig(max_rows_returned=15))
        assert len(_rows(warden.run("select id from orders"))) == 10
        assert len(_rows(warden.run("select id from orders"))) == 10
        assert _code(warden.run("select id from orders").decision) == "BUDGET_EXHAUSTED"

    def test_a_database_error_is_reported_and_recorded(self, warehouse: str) -> None:
        engine = SnowflakeEngine(warehouse)
        warden = Warden(engine, audit=MemoryAuditSink(), dialect="snowflake")  # no table rules
        outcome = warden.run("select id from nosuch")
        assert isinstance(outcome.error, QueryFailed)
        assert isinstance(warden.audit, MemoryAuditSink)
        assert warden.audit.events[0].decision == "failed"


def test_a_config_file_is_all_it_takes(warehouse: str, tmp_path: Path) -> None:
    policy = tmp_path / "warden.yaml"
    policy.write_text(
        f"""\
version: 1
warehouse:
  engine: snowflake
  dsn: {warehouse}
  max_rows: 5
masking:
  key: a-key-for-these-tests-only
default_profile: support
profiles:
  support:
    tables:
      PUBLIC.CUSTOMERS: "*"
    masks:
      PUBLIC.CUSTOMERS.SSN: redact
"""
    )
    warden = build_warden(load_config(policy), audit=MemoryAuditSink())
    assert (warden.dialect, warden.default_schema) == ("snowflake", "PUBLIC")
    outcome = warden.run("select id, ssn from customers order by id")
    assert outcome.decision.sql == "SELECT ID, SSN FROM PUBLIC.CUSTOMERS ORDER BY ID LIMIT 6"
    assert _rows(outcome)[0] == (1, "[REDACTED]")
    assert outcome.result is not None
    assert outcome.result.truncated is True
    assert [table.name for table in warden.tables()] == ["CUSTOMERS"]
