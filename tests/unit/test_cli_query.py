import pytest
from click.testing import CliRunner

from sql_warden import cli as cli_module
from sql_warden.cli import cli
from sql_warden.config import DEFAULT_DSN
from sql_warden.engines import QueryTimeout
from tests.unit.conftest import FakeEngine


def test_query_prints_a_table_and_what_was_rewritten(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["query", "select 1 as id"])
    assert outcome.exit_code == 0, outcome.output
    assert outcome.output.splitlines() == [
        "id",
        "--",
        "1",
        "(1 row, 1 ms, profile all)",
        "note: added LIMIT 101 (row cap 100 + 1 to detect truncation)",
    ]
    assert engines[0].executed == ["SELECT 1 AS id LIMIT 101"]


def test_query_without_rewrites_has_no_notes(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["query", "select 1 as id limit 1"])
    assert outcome.output.splitlines() == ["id", "--", "1", "(1 row, 1 ms, profile all)"]


def test_shape_refusals_never_execute(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["query", "delete from orders"])
    assert outcome.exit_code == 2
    assert outcome.output.splitlines()[1:] == [
        "✗ shape  NOT_A_SELECT: only SELECT queries are allowed, not DELETE",
        "→ refused by shape (profile all)",
    ]
    assert engines[0].executed == []


def test_sqlglot_fallback_warnings_are_silenced(
    engines: list[FakeEngine], caplog: pytest.LogCaptureFixture
) -> None:
    outcome = CliRunner().invoke(cli, ["query", "do $$ begin end $$"])
    assert "NOT_A_SELECT: only SELECT queries are allowed, not DO" in outcome.output
    assert [record for record in caplog.records if record.name == "sqlglot"] == []


def test_query_uses_demo_dsn_and_defaults(engines: list[FakeEngine]) -> None:
    CliRunner().invoke(cli, ["query", "select 1"])
    assert (engines[0].dsn, engines[0].max_rows, engines[0].statement_timeout_ms) == (
        DEFAULT_DSN,
        100,
        5_000,
    )


def test_query_options_and_env_dsn(engines: list[FakeEngine]) -> None:
    CliRunner().invoke(
        cli,
        ["query", "select 1", "--max-rows", "7", "--timeout-ms", "250"],
        env={"SQL_WARDEN_DSN": "postgresql://elsewhere/db"},
    )
    assert (engines[0].dsn, engines[0].max_rows, engines[0].statement_timeout_ms) == (
        "postgresql://elsewhere/db",
        7,
        250,
    )


def test_query_rejects_zero_max_rows(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["query", "select 1", "--max-rows", "0"])
    assert outcome.exit_code == 1
    assert engines == []


def test_refused_query_shows_the_reason_and_never_executes(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["query", "SELEC 1"])
    assert outcome.exit_code == 2
    assert outcome.output.splitlines() == [
        "✗ parse  PARSE_ERROR: Invalid expression / Unexpected token (line 1, col 7)",
        "→ refused by parse (profile all)",
    ]
    assert engines[0].executed == []


def test_engine_errors_become_a_clean_message(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing(dsn: str, **settings: int) -> FakeEngine:
        return FakeEngine(error=QueryTimeout("query cancelled"))

    monkeypatch.setattr(cli_module, "PostgresEngine", failing)
    outcome = CliRunner().invoke(cli, ["query", "select count(*) from orders"])
    assert outcome.exit_code == 1
    assert "Error: query cancelled" in outcome.output
    assert "Traceback" not in outcome.output
