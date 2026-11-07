"""Every request, through the real CLI and MCP server, leaves one row in a real audit database."""

import json
import uuid
from pathlib import Path
from typing import Any

import psycopg
import pytest
from click.testing import CliRunner
from mcp import Client
from mcp_types import Implementation
from psycopg.rows import dict_row

from sql_warden.audit import PostgresAuditSink
from sql_warden.cli import EXIT_ERROR, EXIT_REFUSED, build_warden, cli
from sql_warden.config import load_config
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.server import create_server
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration


def _invoke(
    warehouse: Warehouse, *args: str, config: Path | None = None
) -> tuple[int, dict[str, Any]]:
    env = {"SQL_WARDEN_DSN": warehouse.reader_dsn}
    if config is not None:
        env["SQL_WARDEN_CONFIG"] = str(config)
    outcome = CliRunner().invoke(cli, [*args, "--json"], env=env)
    return outcome.exit_code, json.loads(outcome.output)


def _rows(audit_dsn: str, sql: str) -> list[dict[str, Any]]:
    """Every audit row for sql, as sent."""
    with psycopg.connect(audit_dsn, row_factory=dict_row) as conn:
        return conn.execute("SELECT * FROM audit_events WHERE sql = %s", (sql,)).fetchall()


def _tagged(sql: str) -> str:
    """sql with a unique tag, so its audit rows can't be confused with another test's."""
    return f"{sql} -- {uuid.uuid4()}"


def test_an_allowed_query_is_one_row(warehouse: Warehouse, audit_dsn: str) -> None:
    sql = _tagged("select id, name from products where id <= 3")
    code, payload = _invoke(warehouse, "query", sql)
    assert code == 0
    (row,) = _rows(audit_dsn, sql)
    assert str(row["id"]) == payload["audit_id"]
    assert {key: row[key] for key in _SUMMARY} == {
        "client": "cli",
        "profile": "all",
        "dry_run": False,
        "decision": "allowed",
        "executed_sql": "SELECT id, name FROM products WHERE id <= 3 LIMIT 101",
        "rewrites": ["added LIMIT 101 (row cap 100 + 1 to detect truncation)"],
        "refused_by": None,
        "code": None,
        "reason": None,
        "error": None,
        "rows_returned": 3,
        "truncated": False,
    }
    # The trace stored is the trace returned, timings included (--json leaves out nulls).
    assert row["trace"] == [{"code": None, "reason": None, **step} for step in payload["trace"]]
    assert row["duration_ms"] > 0


def test_a_refusal_is_one_row(warehouse: Warehouse, audit_dsn: str) -> None:
    sql = _tagged("select * from employee_salaries; select 1")
    code, payload = _invoke(warehouse, "query", sql)
    assert code == EXIT_REFUSED
    (row,) = _rows(audit_dsn, sql)
    assert str(row["id"]) == payload["audit_id"]
    assert (row["decision"], row["refused_by"], row["code"]) == (
        "refused",
        "shape",
        "MULTIPLE_STATEMENTS",
    )
    assert row["reason"] == payload["reason"]
    assert (row["executed_sql"], row["rows_returned"]) == (None, None)


def test_a_dry_run_is_one_row(warehouse: Warehouse, audit_dsn: str) -> None:
    sql = _tagged("select count(*) from orders")
    code, payload = _invoke(warehouse, "check", sql)
    assert code == 0
    (row,) = _rows(audit_dsn, sql)
    assert (row["dry_run"], row["decision"]) == (True, "allowed")
    assert row["executed_sql"] == payload["sql"] == "SELECT COUNT(*) FROM orders LIMIT 101"
    assert (row["rows_returned"], row["truncated"]) == (None, None)


def test_a_database_error_is_one_row(warehouse: Warehouse, audit_dsn: str) -> None:
    sql = _tagged("select 100 / (id - 1) from products order by id")
    code, payload = _invoke(warehouse, "query", sql)
    assert code == EXIT_ERROR
    (row,) = _rows(audit_dsn, sql)
    assert (row["decision"], row["error"]) == ("failed", "division by zero")
    assert str(row["id"]) == payload["audit_id"]
    assert 0 < row["cost_estimate"] < 100  # planned before it ran


def test_a_query_too_costly_is_one_row(warehouse: Warehouse, audit_dsn: str) -> None:
    sql = _tagged("select count(*) from orders a cross join orders b")
    code, payload = _invoke(warehouse, "query", sql)
    assert code == EXIT_REFUSED
    (row,) = _rows(audit_dsn, sql)
    assert (row["decision"], row["refused_by"], row["code"]) == ("refused", "cost", "COST_TOO_HIGH")
    assert row["cost_estimate"] > 1e9
    assert row["cost_estimate"] == payload["cost"]["total_cost"]
    assert row["executed_sql"] is None


def test_an_error_while_planning_is_one_row(warehouse: Warehouse, audit_dsn: str) -> None:
    sql = _tagged("select 1 / 0")
    code, payload = _invoke(warehouse, "query", sql)
    assert code == EXIT_REFUSED
    (row,) = _rows(audit_dsn, sql)
    assert (row["decision"], row["code"], row["cost_estimate"]) == ("refused", "PLAN_FAILED", None)
    assert row["reason"] == payload["reason"]


def test_a_timeout_is_one_row(warehouse: Warehouse, audit_dsn: str, tmp_path: Path) -> None:
    # A limit high enough to let the cross join through the cost check, to the timeout.
    config = tmp_path / "warden.yaml"
    config.write_text("version: 1\ncost:\n  max_total_cost: 1000000000000000\n")
    sql = _tagged("select count(*) from orders a cross join orders b")
    code, payload = _invoke(warehouse, "query", sql, "--timeout-ms", "100", config=config)
    assert code == EXIT_ERROR
    (row,) = _rows(audit_dsn, sql)
    assert row["decision"] == "failed"
    assert row["error"] == payload["error"]
    assert "timeout" in row["error"]


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_mcp_calls_name_the_client(
    warehouse: Warehouse, audit_dsn: str, tmp_path: Path, anyio_backend: str
) -> None:
    policy = tmp_path / "warden.yaml"
    policy.write_text(
        f"version: 1\nwarehouse:\n  dsn: {warehouse.reader_dsn}\naudit:\n  dsn: {audit_dsn}\n"
    )
    run_sql, check_sql = _tagged("select 1"), _tagged("select 2")
    info = Implementation(name="claude-code", version="2.1.3")
    async with Client(create_server(build_warden(load_config(policy))), client_info=info) as c:
        await c.call_tool("run_query", {"sql": run_sql})
        await c.call_tool("check_query", {"sql": check_sql})
    (run,) = _rows(audit_dsn, run_sql)
    (check,) = _rows(audit_dsn, check_sql)
    assert (run["client"], run["dry_run"], run["rows_returned"]) == ("claude-code 2.1.3", False, 1)
    assert (check["client"], check["dry_run"]) == ("claude-code 2.1.3", True)


def test_without_the_audit_database_nothing_starts(warehouse: Warehouse) -> None:
    outcome = CliRunner().invoke(
        cli,
        ["query", "select 1"],
        env={
            "SQL_WARDEN_DSN": warehouse.reader_dsn,
            "SQL_WARDEN_AUDIT_DSN": "postgresql://warden_audit:hunter2@127.0.0.1:1/audit",
        },
    )
    assert outcome.exit_code == EXIT_ERROR
    assert outcome.output.startswith(
        "Error: audit database at 127.0.0.1:1/audit as warden_audit: "
        "could not set up the audit table: "
    )
    assert "hunter2" not in outcome.output


def test_an_audit_database_that_goes_away_stops_queries(warehouse: Warehouse) -> None:
    # Started fine, then lost its audit database: nothing more runs.
    sink = PostgresAuditSink("postgresql://nobody:x@127.0.0.1:1/audit", connect_timeout_s=1)
    outcome = Warden(PostgresEngine(warehouse.reader_dsn), audit=sink).run("select 1")
    assert outcome.result is None
    refused = outcome.decision.refused_by
    assert refused is not None
    assert refused.refusal is not None
    assert refused.refusal.code == "AUDIT_UNAVAILABLE"
    assert refused.refusal.reason.startswith("the audit database is unavailable: ")
    assert refused.refusal.reason.endswith("; the query was not run")


def test_rows_are_withheld_when_their_record_cant_be_written(
    warehouse: Warehouse, audit_dsn: str
) -> None:
    # The audit database answers, but its table is gone: the query runs, its record fails.
    sink = PostgresAuditSink(audit_dsn)
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS audit_events")
    try:
        outcome = Warden(PostgresEngine(warehouse.reader_dsn), audit=sink).run(
            "select name from products"
        )
    finally:
        sink.ensure_schema()  # for the tests that come after
        sink.close()
    assert outcome.result is None
    refused = outcome.decision.refused_by
    assert refused is not None
    assert refused.refusal is not None
    assert refused.refusal.code == "AUDIT_UNAVAILABLE"
    assert 'relation "audit_events" does not exist' in refused.refusal.reason
    assert refused.refusal.reason.endswith("the query ran, but its results are withheld")


_SUMMARY = (
    "client",
    "profile",
    "dry_run",
    "decision",
    "executed_sql",
    "rewrites",
    "refused_by",
    "code",
    "reason",
    "error",
    "rows_returned",
    "truncated",
)
