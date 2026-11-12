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
import uvicorn
from click.testing import CliRunner

from sql_warden.audit import MemoryAuditSink
from sql_warden.config import load_config
from sql_warden.models import RefusalCode
from sql_warden.server import QueryResponse
from sql_warden.warden import Warden
from tests.portal.__main__ import main
from tests.portal.app import DOCS, EXAMPLES, PAGE, create_portal_app
from tests.support import serving
from tests.unit.conftest import FakeEngine
from tests.unit.test_access_check import ADMIN, CATALOG, PUBLIC


@dataclass
class PortalClient:
    """Does what index.html does: initialize, notifications/initialized, then tools/call."""

    base_url: str
    endpoint: str = "/mcp"
    """/mcp for the default profile, /p/<profile>/mcp for any profile."""
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
            f"{self.base_url}{self.endpoint}", json.dumps(message).encode(), headers, method="POST"
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
    with serving(create_portal_app(Warden(engine, audit=MemoryAuditSink()))) as base_url:
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


def test_a_table_click_writes_a_query_the_profile_allows() -> None:
    # SELECT * only where every column may be read; else the listed columns.
    assert 't.all_columns ? "*" : t.columns.map(c => c.name).join(", ")' in PAGE.read_text()


def test_the_docs_and_examples_are_served(portal_url: str) -> None:
    with urllib.request.urlopen(f"{portal_url}/docs", timeout=10) as response:
        assert response.headers["content-type"].startswith("text/html")
        assert response.headers["cache-control"] == "no-store"
        assert "<title>portal docs</title>" in response.read().decode()
    with urllib.request.urlopen(f"{portal_url}/examples.json", timeout=10) as response:
        assert response.headers["content-type"] == "application/json"
        assert json.loads(response.read()) == json.loads(EXAMPLES.read_text())


def test_the_page_links_to_the_docs_and_keeps_no_examples_of_its_own() -> None:
    page = PAGE.read_text()
    # A tab of their own, which can still send example links back to this tab by its name.
    assert 'href="/docs" target="sql-warden-docs" rel="opener"' in page
    assert 'window.name = "sql-warden-portal";' in page
    docs = DOCS.read_text()
    assert 'const PORTAL_TAB = "sql-warden-portal";' in docs
    assert docs.count("target: PORTAL_TAB") == 4
    assert '<a href="/" target="sql-warden-portal">' in docs
    assert "EXAMPLES" not in page
    assert 'id="examples"' not in page


def test_each_example_is_complete_and_for_a_profile_the_example_config_has() -> None:
    profiles = set(load_config(Path(__file__).parents[2] / "warden.example.yaml").profiles or ())
    outcomes = {"allowed", "failed", *RefusalCode}
    examples = json.loads(EXAMPLES.read_text())["examples"]
    assert examples
    for example in examples:
        assert {"group", "title", "profile", "sql", "expect"} <= set(example), example
        assert set(example) <= {"group", "title", "profile", "sql", "expect", "look"}, example
        assert example["profile"] in profiles, example["title"]
        assert example["expect"] in outcomes, example["title"]
    titles = [example["title"] for example in examples]
    assert len(titles) == len(set(titles))


def test_the_docs_say_which_transport_each_client_uses() -> None:
    transports = re.findall(r'data-transport="(\w+)"', DOCS.read_text())
    assert transports == ["portal", "stdio", "http", "cli"]


def test_the_docs_list_every_refusal_code_and_response_field() -> None:
    docs = DOCS.read_text()
    assert re.findall(r'data-code="(\w+)"', docs) == list(RefusalCode)
    assert re.findall(r'data-field="(\w+)"', docs) == list(QueryResponse.model_fields)


def test_the_docs_page_only_lists_tools(client: PortalClient) -> None:
    # The docs page's whole exchange: the handshake, then tools/list.
    methods = re.findall(r'method: "([a-z/]+)"', DOCS.read_text())  # JSON-RPC, not HTTP
    assert methods == ["initialize", "notifications/initialized", "tools/list"]
    _, _, messages = client.post({"jsonrpc": "2.0", "id": 99, "method": "tools/list"})
    tools = {tool["name"]: tool for tool in messages[0]["result"]["tools"]}
    assert set(tools) == {"run_query", "check_query", "list_tables", "describe_table"}
    for name in ("run_query", "check_query"):
        assert set(tools[name]["outputSchema"]["properties"]) == set(QueryResponse.model_fields)
    assert tools["run_query"]["inputSchema"]["required"] == ["sql"]


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
    assert [step["check"] for step in payload["trace"]] == ["parse", "shape", "cost"]
    assert payload["cost"] == {
        "total_cost": 1.0,
        "max_total_cost": 1_000_000,
        "est_rows": 1,
        "top_node": "Result",
    }
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


def test_each_connection_is_a_session_and_the_audit_log_says_which(portal_url: str) -> None:
    first, second = PortalClient(portal_url), PortalClient(portal_url)
    first.connect()
    second.connect()
    ids = [
        client.call_tool(tool, sql="select 1")["structuredContent"]["session_id"]
        for client, tool in ((first, "run_query"), (first, "check_query"), (second, "run_query"))
    ]
    assert ids[0] == ids[1] != ids[2]
    assert re.fullmatch(r"[0-9a-f]{32}", ids[0])
    # Never the transport's own id: whoever holds that can use the connection.
    assert first.session_id not in ids
    assert second.session_id not in ids


def test_the_audit_log_records_the_connections_session(engine: FakeEngine) -> None:
    audit = MemoryAuditSink()
    warden = Warden(engine, audit=audit)
    with serving(create_portal_app(warden)) as base_url:
        client = PortalClient(base_url)
        client.connect()
        payload = client.call_tool("run_query", sql="select 1")["structuredContent"]
    (event,) = audit.events
    assert event.session_id == payload["session_id"] != warden.session_id
    assert client.session_id is not None
    assert client.session_id not in repr(event)


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


@pytest.fixture
def profiles_url() -> Iterator[str]:
    wardens = {
        "public": Warden(
            FakeEngine(catalog=CATALOG), audit=MemoryAuditSink(), profile="public", access=PUBLIC
        ),
        "admin": Warden(
            FakeEngine(catalog=CATALOG), audit=MemoryAuditSink(), profile="admin", access=ADMIN
        ),
    }
    with serving(create_portal_app(wardens, default="public")) as base_url:
        yield base_url


def _get_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=10) as response:
        return json.loads(response.read())


class TestProfiles:
    def test_the_page_learns_the_profiles(self, profiles_url: str) -> None:
        assert _get_json(f"{profiles_url}/profiles") == {
            "profiles": ["public", "admin"],
            "default": "public",
        }

    @pytest.mark.parametrize(
        ("profile", "tables"),
        [("public", ["products", "orders", "daily"]), ("admin", [t.name for t in CATALOG])],
    )
    def test_each_profile_has_its_own_server(
        self, profiles_url: str, profile: str, tables: list[str]
    ) -> None:
        client = PortalClient(profiles_url, endpoint=f"/p/{profile}/mcp")
        client.connect()
        listed = client.call_tool("list_tables")["structuredContent"]
        assert listed["profile"] == profile
        assert [t["name"] for t in listed["tables"]] == tables

    def test_compare_is_a_check_under_each_profile(self, profiles_url: str) -> None:
        decisions = {}
        for profile in ("public", "admin"):
            client = PortalClient(profiles_url, endpoint=f"/p/{profile}/mcp")
            client.connect()
            payload = client.call_tool("check_query", sql="select * from employee_salaries")
            decisions[profile] = payload["structuredContent"].get("code", "ALLOWED")
        assert decisions == {"public": "TABLE_NOT_ALLOWED", "admin": "ALLOWED"}

    def test_mcp_is_the_default_profile(self, profiles_url: str) -> None:
        client = PortalClient(profiles_url)
        client.connect()
        assert client.call_tool("list_tables")["structuredContent"]["profile"] == "public"

    def test_a_session_belongs_to_one_profile(self, profiles_url: str) -> None:
        public = PortalClient(profiles_url, endpoint="/p/public/mcp")
        public.connect()
        borrowed = PortalClient(profiles_url, endpoint="/p/admin/mcp", session_id=public.session_id)
        status, _, _ = borrowed.post(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_tables"}}
        )
        assert status == 404

    def test_an_unknown_profile_has_no_server(self, profiles_url: str) -> None:
        status, _, _ = PortalClient(profiles_url, endpoint="/p/root/mcp").post({})
        assert status == 404

    def test_the_page_has_the_picker_and_compare(self) -> None:
        page = PAGE.read_text()
        for needle in (
            'id="profile"',
            'id="compare"',
            "/p/${encodeURIComponent(profile)}/mcp",
        ):
            assert needle in page


class TestLauncherProfiles:
    @pytest.fixture
    def served(self, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        apps: list[Any] = []
        monkeypatch.setattr(uvicorn, "run", lambda app, **_: apps.append(app))
        return apps

    @pytest.fixture
    def policy(self, tmp_path: Path) -> Path:
        path = tmp_path / "warden.yaml"
        path.write_text(
            "version: 1\ndefault_profile: public\nprofiles:\n"
            "  public:\n    tables:\n      public.products: [id]\n"
            '  admin:\n    tables: "*"\n'
        )
        return path

    def test_it_serves_every_profile(self, served: list[Any], policy: Path) -> None:
        outcome = CliRunner().invoke(main, ["--config", str(policy), "--no-open"])
        assert outcome.exit_code == 0, outcome.output
        assert "profiles public, admin" in outcome.output
        assert "no profiles" not in outcome.output
        with serving(served[0]) as base_url:
            assert _get_json(f"{base_url}/profiles") == {
                "profiles": ["public", "admin"],
                "default": "public",
            }

    def test_profile_picks_where_the_page_starts(self, served: list[Any], policy: Path) -> None:
        CliRunner().invoke(main, ["--config", str(policy), "--no-open", "--profile", "admin"])
        with serving(served[0]) as base_url:
            assert _get_json(f"{base_url}/profiles")["default"] == "admin"

    def test_an_unknown_profile_is_an_error(self, served: list[Any], policy: Path) -> None:
        outcome = CliRunner().invoke(main, ["--config", str(policy), "--no-open", "--profile", "x"])
        assert outcome.exit_code == 1
        assert "unknown profile 'x': the config defines public, admin" in outcome.output
        assert served == []

    def test_without_a_config_file_it_serves_the_example_profiles_too(
        self, served: list[Any], engines: list[FakeEngine]
    ) -> None:
        outcome = CliRunner().invoke(main, ["--no-open"])
        assert outcome.exit_code == 0, outcome.output
        assert "profiles all, public, support, admin" in outcome.output
        assert (
            "no config file, so public, support, admin come from warden.example.yaml"
            in outcome.output
        )
        # public connects as its own role, as the example config says; all and admin as the
        # warehouse's reader.
        users = [engine.dsn.split("://")[1].split(":")[0] for engine in engines]
        assert users == ["warden_reader", "warden_public", "warden_reader", "warden_reader"]
        with serving(served[0]) as base_url:
            assert _get_json(f"{base_url}/profiles") == {
                "profiles": ["all", "public", "support", "admin"],
                "default": "all",
            }
            for profile in ("all", "public", "support", "admin"):  # each is its own server
                client = PortalClient(base_url, endpoint=f"/p/{profile}/mcp")
                client.connect()
                listed = client.call_tool("list_tables")["structuredContent"]
                assert listed["profile"] == profile

    def test_without_a_config_file_it_can_start_on_an_example_profile(
        self, served: list[Any]
    ) -> None:
        outcome = CliRunner().invoke(main, ["--no-open", "--profile", "admin"])
        assert outcome.exit_code == 0, outcome.output
        with serving(served[0]) as base_url:
            assert _get_json(f"{base_url}/profiles")["default"] == "admin"
        unknown = CliRunner().invoke(main, ["--no-open", "--profile", "x"])
        assert unknown.exit_code == 1
        assert "unknown profile 'x': the portal serves all, public, support, admin" in (
            unknown.output
        )

    def test_without_profiles_there_is_one(self, served: list[Any], tmp_path: Path) -> None:
        empty = tmp_path / "warden.yaml"
        empty.write_text("version: 1\n")
        outcome = CliRunner().invoke(main, ["--config", str(empty), "--no-open"])
        assert "the config has no profiles, so the page has only 'all' to pick" in outcome.output
        with serving(served[0]) as base_url:
            assert _get_json(f"{base_url}/profiles") == {"profiles": ["all"], "default": "all"}
