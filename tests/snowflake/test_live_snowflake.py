"""SnowflakeEngine against a real account: what no emulator can vouch for.

Skipped unless SNOWFLAKE_DSN is set, to a connection string as in warden.yaml:

    SNOWFLAKE_DSN='snowflake://USER:PASSWORD@ACCOUNT/DATABASE/SCHEMA?warehouse=WH&role=ROLE' \\
        uv run pytest -m snowflake

Everything here only reads: it creates, changes and drops nothing, and needs no particular
tables. It costs a few seconds of the warehouse. These have not yet been run against an
account; when they first are, expect to adjust the engine to what Snowflake really returns.
"""

import os

import pytest

from sql_warden.audit import MemoryAuditSink
from sql_warden.engines import QueryFailed, QueryTimeout
from sql_warden.engines.snowflake import SnowflakeEngine
from sql_warden.warden import Warden

DSN = os.environ.get("SNOWFLAKE_DSN")
pytestmark = [
    pytest.mark.snowflake,
    pytest.mark.skipif(DSN is None, reason="SNOWFLAKE_DSN is not set"),
]


@pytest.fixture(scope="module")
def engine() -> SnowflakeEngine:
    assert DSN is not None
    return SnowflakeEngine(DSN, statement_timeout_ms=20_000, max_rows=5)


def test_it_connects_and_runs_a_query(engine: SnowflakeEngine) -> None:
    result = engine.execute("SELECT 1 AS ONE, CURRENT_SCHEMA() AS S", tag="sql-warden live-test")
    assert result.columns == ("ONE", "S")
    assert result.rows == ((1, engine.default_schema),)


def test_the_row_cap_holds_whatever_the_query_says(engine: SnowflakeEngine) -> None:
    result = engine.execute("SELECT SEQ4() AS N FROM TABLE(GENERATOR(ROWCOUNT => 1000))")
    assert (len(result.rows), result.truncated) == (5, True)


def test_explain_gives_bytes_and_never_runs_the_query(engine: SnowflakeEngine) -> None:
    estimate = engine.explain("SELECT SEQ4() FROM TABLE(GENERATOR(ROWCOUNT => 100000000000))")
    assert estimate.unit == "bytes"
    assert estimate.total_cost >= 0
    assert estimate.top_node
    assert {"GlobalStats", "Operations"} <= set(estimate.raw)


def test_the_catalog_is_readable_and_stored_upper_case(engine: SnowflakeEngine) -> None:
    for table in engine.tables():
        assert table.schema != "INFORMATION_SCHEMA"
        assert table.columns


def test_a_second_statement_is_refused_by_snowflake(engine: SnowflakeEngine) -> None:
    with pytest.raises(QueryFailed):
        engine.execute("SELECT 1; SELECT 2")


def test_a_compile_error_comes_back_as_snowflake_words_it(engine: SnowflakeEngine) -> None:
    with pytest.raises(QueryFailed) as excinfo:
        engine.explain("SELECT * FROM SQL_WARDEN_NO_SUCH_TABLE_7F3A")
    assert "does not exist" in str(excinfo.value)
    assert excinfo.value.sqlstate is not None


def test_the_statement_timeout_cancels_a_slow_query() -> None:
    assert DSN is not None
    quick = SnowflakeEngine(DSN, statement_timeout_ms=1_000)
    with pytest.raises(QueryTimeout):
        quick.execute("SELECT SYSTEM$WAIT(30)")  # straight to the engine: the checks refuse it


def test_the_role_can_be_looked_at(engine: SnowflakeEngine) -> None:
    # Whatever the account's role holds: the three statements run, and say something a
    # server can act on. Run it as a role granted only USAGE and SELECT to see it pass
    # read_only; nothing here asserts that, since the account is yours.
    report = engine.role()
    assert report.role
    assert all(isinstance(line, str) and line for line in report.writes)


def test_through_the_warden(engine: SnowflakeEngine) -> None:
    warden = Warden(
        engine,
        audit=MemoryAuditSink(),
        dialect="snowflake",
        default_schema=engine.default_schema,
    )
    outcome = warden.run("select 1 as one")
    assert outcome.decision.allowed, outcome.decision.refused_by
    assert outcome.decision.sql == "SELECT 1 AS ONE LIMIT 6"
    assert outcome.result is not None
    assert outcome.result.rows == ((1,),)
    refused = warden.run("select system$wait(1)")
    assert refused.result is None
