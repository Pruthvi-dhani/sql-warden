import datetime
import json
import uuid
from decimal import Decimal
from typing import Any

import pytest
from click.testing import CliRunner
from mcp import Client
from mcp_types import CallToolResult, TextContent

from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import cli
from sql_warden.engines import EngineUnavailable, QueryTimeout, Result
from sql_warden.server import create_http_app, create_server, is_loopback, json_value
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _call(engine: FakeEngine, tool: str, **arguments: Any) -> CallToolResult:
    async with Client(create_server(Warden(engine, audit=MemoryAuditSink()))) as client:
        return await client.call_tool(tool, arguments)


def _payload(result: CallToolResult) -> dict[str, Any]:
    assert result.structured_content is not None
    payload: dict[str, Any] = result.structured_content
    return payload


async def test_tools_are_listed_as_read_only() -> None:
    async with Client(create_server(Warden(FakeEngine(), audit=MemoryAuditSink()))) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    assert set(tools) == {"run_query", "check_query", "list_tables", "describe_table"}
    for tool in tools.values():
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.output_schema is not None
        assert tool.description


async def test_server_tells_agents_how_it_works() -> None:
    async with Client(create_server(Warden(FakeEngine(), audit=MemoryAuditSink()))) as client:
        assert client.instructions is not None
        assert "refused" in client.instructions


class TestRunQuery:
    async def test_allowed_query_returns_rows_and_what_ran(self) -> None:
        engine = FakeEngine()
        result = await _call(engine, "run_query", sql="select 1 as id")
        assert result.is_error is False
        payload = _payload(result)
        assert payload["refused"] is False
        assert payload["sql"] == "SELECT 1 AS id LIMIT 101"
        assert payload["rewrites"] == ["added LIMIT 101 (row cap 100 + 1 to detect truncation)"]
        assert payload["result"] == {
            "columns": ["id"],
            "rows": [[1]],
            "row_count": 1,
            "truncated": False,
            "duration_ms": 1.0,
        }
        assert [step["check"] for step in payload["trace"]] == ["parse", "shape", "cost"]
        assert all(step["passed"] for step in payload["trace"])
        assert engine.executed == ["SELECT 1 AS id LIMIT 101"]

    async def test_refusal_is_structured_so_the_agent_can_correct_itself(self) -> None:
        engine = FakeEngine()
        result = await _call(engine, "run_query", sql="delete from orders")
        assert result.is_error is True
        payload = _payload(result)
        assert payload["refused"] is True
        assert (payload["check"], payload["code"], payload["reason"]) == (
            "shape",
            "NOT_A_SELECT",
            "only SELECT queries are allowed, not DELETE",
        )
        assert payload["trace"][-1] == {
            "check": "shape",
            "passed": False,
            "code": "NOT_A_SELECT",
            "reason": "only SELECT queries are allowed, not DELETE",
            "duration_ms": payload["trace"][-1]["duration_ms"],
        }
        assert "sql" not in payload
        assert "result" not in payload
        assert engine.executed == []

    async def test_database_errors_keep_the_decision(self) -> None:
        engine = FakeEngine(error=QueryTimeout("query cancelled after the 5000 ms timeout"))
        result = await _call(engine, "run_query", sql="select id from orders")
        assert result.is_error is True
        payload = _payload(result)
        assert payload["refused"] is False
        assert payload["error"] == "query cancelled after the 5000 ms timeout"
        assert payload["sql"] == "SELECT id FROM orders LIMIT 101"
        assert "result" not in payload

    async def test_truncation_is_reported(self) -> None:
        engine = FakeEngine(
            result=Result(columns=("id",), rows=((1,), (2,)), truncated=True, duration_ms=2.5)
        )
        payload = _payload(await _call(engine, "run_query", sql="select id from orders"))
        assert payload["result"]["truncated"] is True
        assert payload["result"]["row_count"] == 2

    async def test_text_content_is_the_same_json(self) -> None:
        result = await _call(FakeEngine(), "run_query", sql="select 1")
        assert isinstance(result.content[0], TextContent)
        assert json.loads(result.content[0].text) == _payload(result)

    async def test_missing_sql_argument_is_an_error(self) -> None:
        engine = FakeEngine()
        result = await _call(engine, "run_query")
        assert result.is_error is True
        assert engine.executed == []


class TestCheckQuery:
    async def test_allowed_query_shows_the_sql_and_runs_nothing(self) -> None:
        engine = FakeEngine()
        result = await _call(engine, "check_query", sql="select id from orders limit 5000")
        assert result.is_error is False
        payload = _payload(result)
        assert payload["refused"] is False
        assert payload["sql"] == "SELECT id FROM orders LIMIT 101"
        assert payload["rewrites"] == [
            "lowered LIMIT 5000 to 101 (row cap 100 + 1 to detect truncation)"
        ]
        assert "result" not in payload
        assert engine.executed == []

    async def test_a_refusal_is_an_answer_not_an_error(self) -> None:
        result = await _call(FakeEngine(), "check_query", sql="select pg_sleep(60)")
        assert result.is_error is False
        assert _payload(result)["code"] == "FUNCTION_NOT_ALLOWED"


class TestListTables:
    async def test_tables_and_columns(self) -> None:
        result = await _call(FakeEngine(), "list_tables")
        assert result.is_error is False
        assert _payload(result) == {
            "profile": "all",
            "tables": [
                {
                    "schema": "public",
                    "name": "products",
                    "columns": [
                        {"name": "id", "type": "integer"},
                        {"name": "name", "type": "text"},
                    ],
                    "all_columns": True,
                }
            ],
        }

    async def test_unreachable_database_is_a_clean_error(self) -> None:
        engine = FakeEngine(error=EngineUnavailable("could not connect to the database"))
        result = await _call(engine, "list_tables")
        assert result.is_error is True
        assert isinstance(result.content[0], TextContent)
        assert "could not connect to the database" in result.content[0].text


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (True, True),
        (7, 7),
        (1.5, 1.5),
        ("x", "x"),
        (Decimal("6.37"), "6.37"),
        (datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.UTC), "2026-01-02T03:04:05+00:00"),
        (datetime.date(2026, 1, 2), "2026-01-02"),
        (datetime.time(3, 4), "03:04:00"),
        (datetime.timedelta(days=1), "1 day, 0:00:00"),
        (uuid.UUID(int=1), "00000000-0000-0000-0000-000000000001"),
        (b"\x00\xff", "\\x00ff"),
        ([1, Decimal("2")], [1, "2"]),
        ({"a": [datetime.date(2026, 1, 2)]}, {"a": ["2026-01-02"]}),
        (frozenset(), "frozenset()"),
    ],
)
async def test_database_values_become_json(value: object, expected: object) -> None:
    assert json_value(value) == expected
    json.dumps(json_value(value))


@pytest.mark.parametrize(
    ("host", "loopback"),
    [
        ("127.0.0.1", True),
        ("127.0.0.2", True),
        ("::1", True),
        ("localhost", True),
        ("0.0.0.0", False),
        ("::", False),
        ("192.168.1.10", False),
        ("example.com", False),
    ],
)
async def test_loopback_hosts(host: str, loopback: bool) -> None:
    assert is_loopback(host) is loopback


async def test_http_app_refuses_non_loopback_hosts() -> None:
    with pytest.raises(ValueError, match="only listens on loopback"):
        create_http_app(Warden(FakeEngine(), audit=MemoryAuditSink()), host="0.0.0.0")


async def test_serve_refuses_non_loopback_hosts(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["serve", "--transport", "http", "--host", "0.0.0.0"])
    assert outcome.exit_code == 1
    assert "refusing to serve MCP over HTTP on 0.0.0.0" in outcome.output
