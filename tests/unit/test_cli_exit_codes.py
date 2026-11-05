"""Exit codes and --json: what a script or CI job relies on when it calls the CLI."""

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from mcp import Client

from sql_warden import cli as cli_module
from sql_warden.cli import EXIT_ERROR, EXIT_REFUSED, cli
from sql_warden.engines import EngineError, EngineUnavailable, QueryFailed, QueryTimeout
from sql_warden.server import create_server
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine


@pytest.fixture
def failing(monkeypatch: pytest.MonkeyPatch) -> list[EngineError]:
    """Make the next engine the CLI builds fail with the error appended here."""
    errors: list[EngineError] = []

    def factory(dsn: str, **settings: int) -> FakeEngine:
        return FakeEngine(error=errors[0])

    monkeypatch.setattr(cli_module, "PostgresEngine", factory)
    return errors


@pytest.mark.parametrize(
    ("args", "code"),
    [
        (["check", "select 1"], 0),
        (["query", "select 1"], 0),
        (["check", "delete from orders"], EXIT_REFUSED),
        (["query", "delete from orders"], EXIT_REFUSED),
        (["query", "select pg_sleep(1)"], EXIT_REFUSED),
        (["check", "select (1"], EXIT_REFUSED),
        (["check", ""], EXIT_REFUSED),
        (["check", "select 1", "--json"], 0),
        (["check", "delete from orders", "--json"], EXIT_REFUSED),
        (["query", "delete from orders", "--json"], EXIT_REFUSED),
        # Usage mistakes exit 1, not Click's 2, so 2 always means a check refused the query.
        (["query"], EXIT_ERROR),
        (["query", "select 1", "--bogus"], EXIT_ERROR),
        (["query", "select 1", "--max-rows", "0"], EXIT_ERROR),
        (["nosuch"], EXIT_ERROR),
        (["config", "validate", "--nope"], EXIT_ERROR),
        (["--version"], 0),
        (["--help"], 0),
    ],
)
def test_exit_codes(engines: list[FakeEngine], args: list[str], code: int) -> None:
    outcome = CliRunner().invoke(cli, args)
    assert outcome.exit_code == code, outcome.output
    assert outcome.exception is None or isinstance(outcome.exception, SystemExit)


@pytest.mark.parametrize(
    "error",
    [
        QueryFailed('relation "nosuch" does not exist'),
        QueryTimeout("query cancelled after the 5000 ms statement timeout"),
        EngineUnavailable("could not connect to the database: connection refused"),
    ],
)
def test_database_failures_exit_1(failing: list[EngineError], error: EngineError) -> None:
    failing.append(error)
    outcome = CliRunner().invoke(cli, ["query", "select 1"])
    assert outcome.exit_code == EXIT_ERROR
    assert outcome.output == f"Error: {error}\n"


def test_a_broken_config_exits_1(engines: list[FakeEngine], isolated_cli: Path) -> None:
    (isolated_cli / "warden.yaml").write_text("version: 2\n")
    outcome = CliRunner().invoke(cli, ["check", "select 1"])
    assert outcome.exit_code == EXIT_ERROR
    assert engines == []


class TestJson:
    def test_check_prints_the_decision(self, engines: list[FakeEngine]) -> None:
        payload = _json(CliRunner().invoke(cli, ["check", "select 1", "--json"]).output)
        assert payload["refused"] is False
        assert payload["sql"] == "SELECT 1 LIMIT 101"
        assert payload["rewrites"] == ["added LIMIT 101 (row cap 100 + 1 to detect truncation)"]
        assert [step["check"] for step in payload["trace"]] == ["parse", "shape"]
        assert "result" not in payload
        assert engines[0].executed == []

    def test_query_prints_the_rows(self, engines: list[FakeEngine]) -> None:
        payload = _json(CliRunner().invoke(cli, ["query", "select 1 as id", "--json"]).output)
        assert payload["result"] == {
            "columns": ["id"],
            "rows": [[1]],
            "row_count": 1,
            "truncated": False,
            "duration_ms": 1.0,
        }

    def test_a_refusal_names_check_code_and_reason(self, engines: list[FakeEngine]) -> None:
        outcome = CliRunner().invoke(cli, ["query", "delete from orders", "--json"])
        payload = _json(outcome.output)
        assert (payload["refused"], payload["check"], payload["code"]) == (
            True,
            "shape",
            "NOT_A_SELECT",
        )
        assert payload["reason"] == "only SELECT queries are allowed, not DELETE"
        assert engines[0].executed == []

    def test_a_database_failure_is_in_the_json_not_on_stderr(
        self, failing: list[EngineError]
    ) -> None:
        failing.append(QueryFailed("division by zero"))
        outcome = CliRunner().invoke(cli, ["query", "select 1 / 0", "--json"])
        assert outcome.exit_code == EXIT_ERROR
        payload = _json(outcome.output)
        assert payload["refused"] is False
        assert payload["error"] == "division by zero"
        assert "result" not in payload

    @pytest.mark.anyio
    @pytest.mark.parametrize("anyio_backend", ["asyncio"])
    @pytest.mark.parametrize("sql", ["select 1 as id", "select 1; select 2", "select pg_sleep(1)"])
    async def test_query_json_is_what_run_query_returns(
        self, engines: list[FakeEngine], anyio_backend: str, sql: str
    ) -> None:
        printed = _json(CliRunner().invoke(cli, ["query", sql, "--json"]).output)
        async with Client(create_server(Warden(FakeEngine()))) as client:
            returned = (await client.call_tool("run_query", {"sql": sql})).structured_content
        assert returned is not None
        assert _without_timings(printed) == _without_timings(returned)


def _json(output: str) -> dict[str, Any]:
    """The output must be exactly one line of JSON."""
    assert output.count("\n") == 1, output
    payload: dict[str, Any] = json.loads(output)
    return payload


def _without_timings(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {k: _without_timings(v) for k, v in payload.items() if k != "duration_ms"}
    if isinstance(payload, list):
        return [_without_timings(item) for item in payload]
    return payload
