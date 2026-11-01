"""The MCP server over its real transports: HTTP on a local port, and stdio in a subprocess."""

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest
import uvicorn
from mcp import Client, StdioServerParameters

from sql_warden.server import create_http_app
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine

pytestmark = pytest.mark.anyio

UNREACHABLE_DSN = "postgresql://nobody:x@127.0.0.1:1/none"
INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def engine() -> FakeEngine:
    return FakeEngine()


@pytest.fixture
def http_url(engine: FakeEngine) -> Iterator[str]:
    """The HTTP app served by uvicorn on a free loopback port, in a background thread."""
    config = uvicorn.Config(
        create_http_app(Warden(engine)), host="127.0.0.1", port=0, log_level="warning"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(timeout=10)


class TestHttp:
    async def test_a_client_can_list_tools_and_run_a_query(
        self, http_url: str, engine: FakeEngine
    ) -> None:
        async with Client(http_url) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            result = await client.call_tool("run_query", {"sql": "select 1 as id"})
        assert names == {"run_query", "check_query", "list_tables"}
        assert result.structured_content is not None
        assert result.structured_content["result"]["rows"] == [[1]]
        assert engine.executed == ["SELECT 1 AS id LIMIT 101"]

    async def test_refusals_come_back_structured(self, http_url: str) -> None:
        async with Client(http_url) as client:
            result = await client.call_tool("run_query", {"sql": "select 1; select 2"})
        assert result.is_error is True
        assert result.structured_content is not None
        assert result.structured_content["code"] == "MULTIPLE_STATEMENTS"

    def test_the_legacy_handshake_works_from_plain_http(self, http_url: str) -> None:
        # What a browser page does: plain JSON-RPC, no SDK.
        status, headers = _post(http_url, Origin=http_url.removesuffix("/mcp"))
        assert status == 200
        assert "mcp-session-id" in headers

    def test_requests_from_other_origins_are_refused(self, http_url: str) -> None:
        # A web page on another site must not reach the server through the user's browser.
        assert _post(http_url, Origin="http://evil.example")[0] == 403

    def test_requests_for_other_hosts_are_refused(self, http_url: str) -> None:
        # DNS rebinding: evil.example resolving to 127.0.0.1 still sends Host: evil.example.
        port = http_url.split(":")[2].split("/")[0]
        assert _post(http_url, Host=f"evil.example:{port}")[0] == 421


class TestStdio:
    async def test_the_cli_serves_over_stdio(self) -> None:
        # No database: listing tools and dry runs work, a real query reports the failure.
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "sql_warden", "serve", "--dsn", UNREACHABLE_DSN],
        )
        async with Client(params) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            checked = await client.call_tool("check_query", {"sql": "select 1"})
            ran = await client.call_tool("run_query", {"sql": "select 1"})
        assert names == {"run_query", "check_query", "list_tables"}
        assert _structured(checked)["sql"] == "SELECT 1 LIMIT 101"
        assert ran.is_error is True
        assert "could not connect to the database" in _structured(ran)["error"]


def _post(url: str, **headers: str) -> tuple[int, dict[str, str]]:
    """POST an initialize request; the status and lower-cased response headers."""
    request = urllib.request.Request(
        url,
        data=json.dumps(INITIALIZE).encode(),
        headers={"Content-Type": "application/json", **MCP_HEADERS, **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, {}


def _structured(result: Any) -> dict[str, Any]:
    assert result.structured_content is not None
    content: dict[str, Any] = result.structured_content
    return content
