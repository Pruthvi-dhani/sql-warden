"""The MCP server over its real transports: HTTP on a local port, and stdio in a subprocess."""

import json
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest
from mcp import Client

from sql_warden.audit import MemoryAuditSink
from sql_warden.server import create_http_app
from sql_warden.warden import Warden
from tests.support import TOOLS, serving
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
    with serving(create_http_app(Warden(engine, audit=MemoryAuditSink()))) as base_url:
        yield f"{base_url}/mcp"


class TestHttp:
    async def test_a_client_can_list_tools_and_run_a_query(
        self, http_url: str, engine: FakeEngine
    ) -> None:
        async with Client(http_url) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            result = await client.call_tool("run_query", {"sql": "select 1 as id"})
        assert names == TOOLS
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
    def test_serve_wont_start_without_its_audit_database(self) -> None:
        # Serving over stdio itself is tested against real databases, in the integration tests.
        done = subprocess.run(
            [sys.executable, "-m", "sql_warden", "serve", "--audit-dsn", UNREACHABLE_DSN],
            input="",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert done.returncode == 1
        assert done.stdout == ""  # it never spoke MCP
        assert done.stderr.startswith("Error: audit database at 127.0.0.1:1/none as nobody: ")
        assert "won't run without its audit database" in done.stderr


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
