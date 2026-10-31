from datetime import datetime

import psycopg
import pytest
from click.testing import CliRunner

from sql_warden.cli import cli
from sql_warden.engines import EngineUnavailable, QueryFailed, QueryTimeout
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration


def test_select_returns_columns_and_typed_rows(warehouse: Warehouse) -> None:
    result = PostgresEngine(warehouse.reader_dsn).execute(
        "SELECT id, email, created_at FROM customers WHERE id <= 2 ORDER BY id"
    )
    assert result.columns == ("id", "email", "created_at")
    assert [row[:2] for row in result.rows] == [
        (1, "customer1@example.com"),
        (2, "customer2@example.com"),
    ]
    assert isinstance(result.rows[0][2], datetime)
    assert result.truncated is False
    assert result.duration_ms > 0


def test_rows_are_capped_and_flagged(warehouse: Warehouse) -> None:
    result = PostgresEngine(warehouse.reader_dsn, max_rows=5).execute("SELECT id FROM orders")
    assert len(result.rows) == 5
    assert result.truncated is True


def test_exactly_max_rows_is_not_truncated(warehouse: Warehouse) -> None:
    result = PostgresEngine(warehouse.reader_dsn, max_rows=50).execute(
        "SELECT id FROM employee_salaries"
    )
    assert len(result.rows) == 50
    assert result.truncated is False


def test_statement_timeout_cancels_slow_queries(warehouse: Warehouse) -> None:
    engine = PostgresEngine(warehouse.reader_dsn, statement_timeout_ms=200)
    with pytest.raises(QueryTimeout, match="200 ms"):
        engine.execute("SELECT pg_sleep(5)")


def test_transaction_is_read_only_even_for_a_privileged_role(warehouse: Warehouse) -> None:
    # The admin role can write; the engine's READ ONLY transaction still stops it.
    with pytest.raises(QueryFailed) as caught:
        PostgresEngine(warehouse.admin_dsn).execute("SELECT lo_create(0)")
    assert caught.value.sqlstate == "25006"  # read_only_sql_transaction


def test_non_query_statements_are_rejected_and_change_nothing(warehouse: Warehouse) -> None:
    with pytest.raises(QueryFailed):
        PostgresEngine(warehouse.admin_dsn).execute("DELETE FROM products")
    with psycopg.connect(warehouse.admin_dsn) as conn:
        assert conn.execute("SELECT count(*) FROM products").fetchone() == (200,)


def test_syntax_errors_are_reported(warehouse: Warehouse) -> None:
    with pytest.raises(QueryFailed) as caught:
        PostgresEngine(warehouse.reader_dsn).execute("SELEC 1")
    assert caught.value.sqlstate == "42601"  # syntax_error
    assert "syntax error" in str(caught.value)


def test_engine_is_reusable_after_a_failure(warehouse: Warehouse) -> None:
    engine = PostgresEngine(warehouse.reader_dsn)
    with pytest.raises(QueryFailed):
        engine.execute("SELECT * FROM no_such_table")
    assert engine.execute("SELECT 1 AS one").rows == ((1,),)


def test_unreachable_database() -> None:
    engine = PostgresEngine("postgresql://nobody:x@127.0.0.1:1/none", connect_timeout_s=2)
    with pytest.raises(EngineUnavailable, match="could not connect"):
        engine.execute("SELECT 1")


def test_cli_query_end_to_end(warehouse: Warehouse) -> None:
    outcome = CliRunner().invoke(
        cli,
        ["query", "SELECT id, name FROM products ORDER BY id", "--max-rows", "2"],
        env={"SQL_WARDEN_DSN": warehouse.reader_dsn},
    )
    assert outcome.exit_code == 0, outcome.output
    lines = outcome.output.splitlines()
    assert lines[:4] == ["id | name", "---+----------", "1  | Product 1", "2  | Product 2"]
    assert lines[4].startswith("(2 rows, truncated at the row cap, ")


def test_warden_runs_allowed_queries_and_stops_malformed_ones(warehouse: Warehouse) -> None:
    warden = Warden(PostgresEngine(warehouse.reader_dsn))
    allowed = warden.run("SELECT count(*) FROM products")
    assert allowed.result is not None
    assert allowed.result.rows == ((200,),)
    refused = warden.run("SELECT count(* FROM products")
    assert refused.result is None
    refused_by = refused.decision.refused_by
    assert refused_by is not None
    assert refused_by.check == "parse"
