"""The portal launcher, and the JSON-RPC exchange the page makes, replayed over real HTTP.

The page's JavaScript is kept thin and checked by hand; these tests pin down everything it
relies on: the page is served, the MCP handshake works from plain HTTP, tool calls return the
payloads it renders, and an expired session gets a 404 so the page knows to reconnect.
"""

import json
import re
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sql_warden.warden import Warden
from tests.portal.__main__ import main
from tests.portal.app import PAGE, create_portal_app
from tests.support import serving
from tests.unit.conftest import FakeEngine


@dataclass
class PortalClient:
    """Does what index.html does: initialize, notifications/initialized, then tools/call."""

    base_url: str
    session_id: str | None = None
    protocol_version: str = "2025-06-18"
    next_id: int = 1
    server_info: dict[str, Any] = field(default_factory=dict)

    def post(self, message: dict[str, Any]) -> tuple[int, dict[str, str], list[dict[str, Any]]]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Origin": self.base_url,  # a browser sends it on every fetch POST
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
            headers["MCP-Protocol-Version"] = self.protocol_version
        request = urllib.request.Request(
            f"{self.base_url}/mcp", json.dumps(message).encode(), headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                body = response.read().decode()
                response_headers = {k.lower(): v for k, v in response.headers.items()}
                return (
                    response.status,
                    response_headers,
                    parse_messages(response_headers.get("content-type", ""), body),
                )
        except urllib.error.HTTPError as exc:
            return exc.code, {}, []

    def connect(self) -> None:
        status, headers, messages = self.post(
            {
                "jsonrpc": "2.0",
                "id": self._id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": self.protocol_version,
                    "capabilities": {},
                    "clientInfo": {"name": "sql-warden-portal", "version": "1"},
                },
            }
        )
        assert status == 200
        result = messages[0]["result"]
        self.session_id = headers["mcp-session-id"]
        self.protocol_version = result["protocolVersion"]
        self.server_info = result["serverInfo"]
        status, _, _ = self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert status == 202

    def call_tool(self, name: str, **arguments: Any) -> dict[str, Any]:
        request_id = self._id()
        status, _, messages = self.post(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        assert status == 200, status
        (reply,) = [m for m in messages if m.get("id") == request_id]
        result: dict[str, Any] = reply["result"]
        return result

    def _id(self) -> int:
        self.next_id += 1
        return self.next_id - 1


def parse_messages(content_type: str, text: str) -> list[dict[str, Any]]:
    """The page's parseMessages: plain JSON, or SSE events whose data lines are JSON."""
    if not text.strip():
        return []
    if "text/event-stream" not in content_type:
        return [json.loads(text)]
    messages = []
    for event in re.split(r"\r?\n\r?\n", text):
        data = [line[5:].lstrip() for line in re.split(r"\r?\n", event) if line.startswith("data:")]
        if data:
            messages.append(json.loads("\n".join(data)))
    return messages


@pytest.fixture
def engine() -> FakeEngine:
    return FakeEngine()


@pytest.fixture
def portal_url(engine: FakeEngine) -> Iterator[str]:
    with serving(create_portal_app(Warden(engine))) as base_url:
        yield base_url


@pytest.fixture
def client(portal_url: str) -> PortalClient:
    client = PortalClient(portal_url)
    client.connect()
    return client


def test_the_page_is_served_at_the_root(portal_url: str) -> None:
    with urllib.request.urlopen(f"{portal_url}/", timeout=10) as response:
        assert response.headers["content-type"].startswith("text/html")
        assert response.headers["cache-control"] == "no-store"
        assert "<title>test portal</title>" in response.read().decode()


def test_the_page_only_calls_tools_the_server_has() -> None:
    called = set(re.findall(r'callTool\("(\w+)"', PAGE.read_text()))
    called |= set(re.findall(r'submit\("(\w+)"', PAGE.read_text()))
    assert called == {"run_query", "check_query", "list_tables"}


def test_the_handshake_names_the_server(client: PortalClient) -> None:
    assert client.server_info["name"] == "sql-warden"
    assert client.session_id


def test_list_tables_for_the_sidebar(client: PortalClient) -> None:
    result = client.call_tool("list_tables")
    assert result["structuredContent"]["tables"][0]["name"] == "products"


def test_run_returns_what_the_page_renders(client: PortalClient, engine: FakeEngine) -> None:
    result = client.call_tool("run_query", sql="select 1 as id")
    payload = result["structuredContent"]
    assert result["isError"] is False
    assert payload["sql"] == "SELECT 1 AS id LIMIT 101"
    assert payload["rewrites"]
    assert [step["check"] for step in payload["trace"]] == ["parse", "shape"]
    assert payload["result"]["rows"] == [[1]]
    assert engine.executed == ["SELECT 1 AS id LIMIT 101"]


def test_check_runs_nothing(client: PortalClient, engine: FakeEngine) -> None:
    payload = client.call_tool("check_query", sql="select 1")["structuredContent"]
    assert payload["refused"] is False
    assert "result" not in payload
    assert engine.executed == []


def test_refusals_carry_check_code_and_reason(client: PortalClient) -> None:
    result = client.call_tool("run_query", sql="select 1; delete from orders")
    assert result["isError"] is True
    payload = result["structuredContent"]
    assert (payload["check"], payload["code"]) == ("shape", "MULTIPLE_STATEMENTS")
    assert payload["trace"][-1]["passed"] is False


def test_an_unknown_session_gets_404_so_the_page_reconnects(portal_url: str) -> None:
    stale = PortalClient(portal_url, session_id="0" * 32)
    status, _, _ = stale.post(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_tables"}}
    )
    assert status == 404


def test_other_origins_cannot_use_the_portals_mcp_endpoint(portal_url: str) -> None:
    client = PortalClient(portal_url)
    request = urllib.request.Request(
        f"{portal_url}/mcp",
        b"{}",
        {"Content-Type": "application/json", "Origin": "http://evil.example"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(request, timeout=10)
    assert caught.value.code == 403
    assert client.session_id is None


def test_launcher_options() -> None:
    outcome = CliRunner().invoke(main, ["--help"])
    assert outcome.exit_code == 0
    for option in ("--config", "--dsn", "--max-rows", "--timeout-ms", "--port", "--no-open"):
        assert option in outcome.output


def test_launcher_reports_a_broken_config(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 2")
    outcome = CliRunner().invoke(main, ["--config", str(bad), "--no-open"])
    assert outcome.exit_code == 1
    assert "version: Input should be 1" in outcome.output
