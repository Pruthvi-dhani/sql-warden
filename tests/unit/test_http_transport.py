"""The HTTP transport as several clients meet it at once: each connection its own session,
none of them in another's way, and the limits that keep one client from using the server up.
"""

import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import anyio
import pytest
import uvicorn
from click.testing import CliRunner
from mcp import Client

from sql_warden import cli as cli_module
from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import cli
from sql_warden.config import BudgetConfig, ConfigError, parse_config
from sql_warden.engines import Result
from sql_warden.server import MAX_REQUEST_BYTES, create_http_app
from sql_warden.warden import Warden
from tests.support import serving
from tests.unit.conftest import AuditSinks, FakeEngine

pytestmark = pytest.mark.anyio

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
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


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class SlowEngine(FakeEngine):
    """Holds a query that says `slow` until it is released, as a long query holds its
    connection."""

    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def execute(self, sql: str, *, tag: str | None = None) -> Result:
        if "slow" in sql:
            self.started.set()
            assert self.release.wait(timeout=20), "the slow query was never released"
        return super().execute(sql, tag=tag)


@contextmanager
def _served(warden: Warden, **settings: Any) -> Iterator[str]:
    with serving(create_http_app(warden, **settings)) as base_url:
        yield f"{base_url}/mcp"


def _warden(engine: FakeEngine | None = None, **settings: Any) -> Warden:
    return Warden(engine or FakeEngine(), audit=MemoryAuditSink(), **settings)


def _events(warden: Warden) -> list[Any]:
    audit = warden.audit
    assert isinstance(audit, MemoryAuditSink)
    return list(audit.events)


def _structured(result: Any) -> dict[str, Any]:
    assert result.structured_content is not None
    content: dict[str, Any] = result.structured_content
    return content


def _post(url: str, body: bytes, **headers: str) -> tuple[int, dict[str, str]]:
    """POST body; the status and lower-cased response headers."""
    request = urllib.request.Request(
        url, data=body, headers={**MCP_HEADERS, **headers}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()  # to the end: the answer is a stream, and the call ends with it
            return response.status, {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}


def _connect(url: str) -> tuple[int, str | None]:
    """Open a session the way a client does; the status, and the transport's id for it."""
    status, headers = _post(url, json.dumps(INITIALIZE).encode())
    return status, headers.get("mcp-session-id")


def _call(url: str, transport_id: str, sql: str) -> int:
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "check_query", "arguments": {"sql": sql}},
    }
    return _post(url, json.dumps(call).encode(), **{"Mcp-Session-Id": transport_id})[0]


class TestClientsThatConnect:
    """The protocol before 2026-07-28: a client opens a connection with a handshake, and the
    transport gives the connection an id. That connection is the session."""

    async def test_each_connection_is_its_own_session(self) -> None:
        warden = _warden()
        with _served(warden) as url:
            async with Client(url, mode="legacy") as one, Client(url, mode="legacy") as other:
                first = _structured(await one.call_tool("run_query", {"sql": "select 1"}))
                again = _structured(await one.call_tool("check_query", {"sql": "select 2"}))
                second = _structured(await other.call_tool("run_query", {"sql": "select 3"}))
        assert first["session_id"] == again["session_id"]
        assert second["session_id"] != first["session_id"]
        # And the audit log says whose each request was.
        recorded = {event.sql: event.session_id for event in _events(warden)}
        assert recorded == {
            "select 1": first["session_id"],
            "select 2": first["session_id"],
            "select 3": second["session_id"],
        }
        # Neither is the server's own session, which stdio and the CLI use.
        assert warden.session_id not in recorded.values()

    async def test_one_clients_budget_is_not_anothers(self) -> None:
        warden = _warden(budget=BudgetConfig(max_queries=1))
        with _served(warden) as url:
            async with Client(url, mode="legacy") as one, Client(url, mode="legacy") as other:
                await one.call_tool("run_query", {"sql": "select 1"})
                spent = _structured(await one.call_tool("run_query", {"sql": "select 1"}))
                fresh = await other.call_tool("run_query", {"sql": "select 1"})
                status = (await one.call_tool("budget_status", {})).structured_content
        assert spent["code"] == "BUDGET_EXHAUSTED"
        assert fresh.is_error is False
        assert status is not None
        assert status["budget"]["exhausted"] == "max_queries"


class TestClientsThatDont:
    """The protocol from 2026-07-28 on has no connections: each request stands alone, with
    no handshake before it and no session id on it. Nothing on the wire says two requests
    came from the same client, so until callers have identities they are all one session,
    the server's own."""

    async def test_every_request_is_in_the_servers_one_session(self) -> None:
        warden = _warden()
        with _served(warden) as url:
            async with Client(url) as one, Client(url) as other:
                assert one.protocol_version == "2026-07-28"
                first = _structured(await one.call_tool("run_query", {"sql": "select 1"}))
                second = _structured(await other.call_tool("run_query", {"sql": "select 2"}))
        assert first["session_id"] == second["session_id"] == warden.session_id
        assert {event.session_id for event in _events(warden)} == {warden.session_id}

    async def test_so_they_share_one_budget(self) -> None:
        # The limit still holds for the server as a whole: it is never a way around it.
        warden = _warden(budget=BudgetConfig(max_queries=1))
        with _served(warden) as url:
            async with Client(url) as one, Client(url) as other:
                first = await one.call_tool("run_query", {"sql": "select 1"})
                second = _structured(await other.call_tool("run_query", {"sql": "select 1"}))
        assert first.is_error is False
        assert second["code"] == "BUDGET_EXHAUSTED"

    async def test_each_request_still_says_which_client_sent_it(self) -> None:
        warden = _warden()
        with _served(warden) as url:
            async with Client(url) as client:
                await client.call_tool("run_query", {"sql": "select 1"})
        (event,) = _events(warden)
        assert event.client is not None
        assert event.client.startswith("mcp ")  # the SDK client's own name and version


@pytest.mark.parametrize("mode", ["legacy", "auto"])
async def test_a_slow_query_holds_up_nobody_else(mode: str) -> None:
    engine = SlowEngine()
    results: dict[str, Any] = {}
    with _served(_warden(engine)) as url:
        async with (
            Client(url, mode=mode) as slow,
            Client(url, mode=mode) as quick,
            anyio.create_task_group() as tasks,
        ):

            async def run_slow() -> None:
                results["slow"] = await slow.call_tool("run_query", {"sql": "select 1 as slow"})

            tasks.start_soon(run_slow)
            assert await anyio.to_thread.run_sync(engine.started.wait, 10)
            # The slow one is still running, and this one comes back.
            with anyio.fail_after(10):
                answered = await quick.call_tool("run_query", {"sql": "select 2"})
            assert answered.is_error is False
            assert "slow" not in results
            engine.release.set()
    assert results["slow"].is_error is False
    assert engine.executed == ["SELECT 2 LIMIT 101", "SELECT 1 AS slow LIMIT 101"]


class TestSessionIds:
    def test_the_session_id_in_a_response_does_not_open_the_connection(self) -> None:
        # Responses and the audit log carry sql-warden's id for the session. It is made from
        # the transport's, not the same: knowing it lets nobody send requests as that client.
        warden = _warden()
        with _served(warden) as url:
            status, transport_id = _connect(url)
            assert (status, transport_id is not None) == (200, True)
            assert transport_id is not None
            assert _call(url, transport_id, "select 1") == 200
            (event,) = _events(warden)
            assert event.session_id != transport_id
            assert _call(url, event.session_id, "select 1") == 404
        assert len(_events(warden)) == 1

    def test_a_made_up_session_id_is_no_session(self) -> None:
        # A client can't pick its id, so it can't pick a fresh budget or someone else's.
        warden = _warden()
        with _served(warden) as url:
            assert _call(url, "nightly-report", "select 1") == 404
            assert _call(url, "0" * 32, "select 1") == 404
        assert _events(warden) == []

    def test_a_request_without_one_is_refused(self) -> None:
        with _served(_warden()) as url:
            call = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
            assert _post(url, json.dumps(call).encode())[0] == 400


class TestLimits:
    def test_a_request_too_large_is_not_read(self) -> None:
        warden = _warden()
        with _served(warden) as url:
            _, transport_id = _connect(url)
            assert transport_id is not None
            call = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "check_query",
                    "arguments": {"sql": "select 1 /*" + "x" * MAX_REQUEST_BYTES + "*/"},
                },
            }
            status, _ = _post(url, json.dumps(call).encode(), **{"Mcp-Session-Id": transport_id})
        assert status == 413
        assert _events(warden) == []

    def test_the_largest_query_the_checks_read_fits(self) -> None:
        # 20,000 characters, each of them four bytes long.
        warden = _warden()
        with _served(warden) as url:
            _, transport_id = _connect(url)
            assert transport_id is not None
            sql = "select '" + "\U0001f512" * 19_989 + "'"
            assert len(sql) == 19_998
            assert _call(url, transport_id, sql) == 200
        (event,) = _events(warden)
        assert event.decision == "allowed"

    def test_no_more_sessions_than_the_server_keeps(self) -> None:
        with _served(_warden(), max_sessions=2) as url:
            (_, first), (_, second) = _connect(url), _connect(url)
            assert first is not None
            assert second is not None
            assert _connect(url) == (503, None)
            # The ones that are open go on working.
            assert _call(url, first, "select 1") == 200
            # And one that closes makes room.
            closing = urllib.request.Request(
                url, headers={**MCP_HEADERS, "Mcp-Session-Id": second}, method="DELETE"
            )
            with urllib.request.urlopen(closing, timeout=10) as response:
                assert response.status == 200
            assert _connect(url)[0] == 200

    def test_a_connection_that_goes_quiet_is_closed(self) -> None:
        warden = _warden()
        with _served(warden, session_idle_s=0.3) as url:
            _, transport_id = _connect(url)
            assert transport_id is not None
            assert _call(url, transport_id, "select 1") == 200
            deadline = time.monotonic() + 10
            while _call(url, transport_id, "select 2") != 404:
                assert time.monotonic() < deadline, "the idle session was never closed"
                time.sleep(0.5)
            # Connecting again is a new session: what the old one used is not carried over.
            _, again = _connect(url)
            assert again is not None
            assert again != transport_id
            assert _call(url, again, "select 3") == 200
        sessions = {event.sql: event.session_id for event in _events(warden)}
        assert sessions["select 3"] != sessions["select 1"]


@pytest.fixture
def served_with(monkeypatch: pytest.MonkeyPatch, audit_sinks: AuditSinks) -> list[dict[str, Any]]:
    """Stands in for uvicorn in the CLI, and collects what `serve` would have run it with."""
    runs: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **settings: runs.append(settings))
    monkeypatch.setattr(cli_module, "PostgresEngine", lambda dsn, **_: FakeEngine(dsn))
    return runs


def _policy(tmp_path: Path, server: str) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(f"version: 1\n{server}")
    return str(path)


class TestServerConfig:
    def test_the_defaults(self) -> None:
        server = parse_config("version: 1\n").server
        assert (server.host, server.port) == ("127.0.0.1", 8000)

    def test_serve_listens_where_the_config_says(
        self, served_with: list[dict[str, Any]], tmp_path: Path
    ) -> None:
        policy = _policy(tmp_path, "server:\n  host: localhost\n  port: 9321\n")
        outcome = CliRunner().invoke(cli, ["--config", policy, "serve", "--transport", "http"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.stderr.splitlines() == [
            "sql-warden MCP server on http://localhost:9321/mcp, profile all (Ctrl+C stops it)"
        ]
        (run,) = served_with
        assert (run["host"], run["port"]) == ("localhost", 9321)
        assert run["server_header"] is False  # it doesn't say what it runs on

    def test_the_flags_win(self, served_with: list[dict[str, Any]], tmp_path: Path) -> None:
        policy = _policy(tmp_path, "server:\n  host: localhost\n  port: 9321\n")
        outcome = CliRunner().invoke(
            cli,
            ["--config", policy, "serve", "--transport", "http", "--host", "::1", "--port", "7"],
        )
        assert outcome.exit_code == 0, outcome.output
        assert "http://[::1]:7/mcp" in outcome.stderr
        (run,) = served_with
        assert (run["host"], run["port"]) == ("::1", 7)

    def test_without_either_it_is_the_default(self, served_with: list[dict[str, Any]]) -> None:
        assert CliRunner().invoke(cli, ["serve", "--transport", "http"]).exit_code == 0
        (run,) = served_with
        assert (run["host"], run["port"]) == ("127.0.0.1", 8000)

    @pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "warden.example.com"])
    def test_a_host_other_machines_can_reach_is_a_config_error(self, host: str) -> None:
        with pytest.raises(ConfigError) as excinfo:
            parse_config(f'version: 1\nserver:\n  host: "{host}"\n')
        assert str(excinfo.value) == (
            f"config: invalid config\n  (top level): server.host is {host}, which other "
            "machines can reach: without an auth section sql-warden only listens on loopback "
            "(127.0.0.1, ::1 or localhost): whoever could reach the port would get everything "
            "its profile may read"
        )

    def test_nor_does_the_flag_get_around_it(self, served_with: list[dict[str, Any]]) -> None:
        outcome = CliRunner().invoke(cli, ["serve", "--transport", "http", "--host", "0.0.0.0"])
        assert outcome.exit_code == 1
        assert outcome.output == (
            "Error: refusing to serve MCP over HTTP on 0.0.0.0: without an auth section "
            "sql-warden only listens on loopback (127.0.0.1, ::1 or localhost): whoever could "
            "reach the port would get everything its profile may read\n"
        )
        assert served_with == []

    def test_validate_says_where_it_would_listen(self, tmp_path: Path) -> None:
        policy = _policy(tmp_path, 'server:\n  host: "::1"\n  port: 9321\n')
        outcome = CliRunner().invoke(cli, ["config", "validate", policy])
        assert outcome.exit_code == 0, outcome.output
        assert "  server:    http on [::1]:9321, this machine only" in outcome.output.splitlines()
        # Left out of the file, it is left out of the summary: stdio servers have no use for it.
        bare = CliRunner().invoke(cli, ["config", "validate", _policy(tmp_path, "")])
        assert "server:" not in bare.output

    def test_validate_refuses_a_host_other_machines_can_reach(self, tmp_path: Path) -> None:
        policy = _policy(tmp_path, "server:\n  host: 0.0.0.0\n")
        outcome = CliRunner().invoke(cli, ["config", "validate", policy])
        assert outcome.exit_code == 1
        assert "server.host is 0.0.0.0, which other machines can reach" in outcome.output

    @pytest.mark.parametrize("port", ["0", "65536", "-1", "http"])
    def test_a_port_that_isnt_one(self, port: str) -> None:
        with pytest.raises(ConfigError, match=r"server\.port"):
            parse_config(f"version: 1\nserver:\n  port: {port}\n")

    def test_an_unknown_key_is_an_error(self) -> None:
        with pytest.raises(ConfigError, match=r"server\.tls_cert"):
            parse_config("version: 1\nserver:\n  tls_cert: /etc/cert.pem\n")

    @pytest.mark.parametrize(
        "server",
        ["allowed_hosts: [warden.example.com]", "allowed_origins: [https://portal.example.com]"],
    )
    def test_letting_callers_in_from_elsewhere_needs_auth(self, server: str) -> None:
        with pytest.raises(ConfigError, match="come with an auth section"):
            parse_config(f"version: 1\nserver:\n  {server}\n")

    @pytest.mark.parametrize(
        ("server", "problem"),
        [
            ("allowed_hosts: [https://warden.example.com]", "is not a host name"),
            ("allowed_hosts: ['warden.example.com:443']", "is not a host name"),
            ("allowed_origins: [portal.example.com]", "is not an origin"),
            ("allowed_origins: ['https://portal.example.com/app']", "is not an origin"),
        ],
    )
    def test_names_and_origins_are_checked(self, server: str, problem: str) -> None:
        with pytest.raises(ConfigError, match=problem):
            parse_config(f"version: 1\nserver:\n  {server}\n")

    def test_beyond_loopback_needs_the_names_it_is_reached_by(self) -> None:
        auth = (
            "profiles:\n  public:\n    tables: {}\nauth:\n  api_keys:\n"
            "    - {name: bot, profile: public, sha256: " + "a" * 64 + "}\n"
        )
        with pytest.raises(ConfigError, match=r"list in server\.allowed_hosts"):
            parse_config(f"version: 1\n{auth}server:\n  host: 0.0.0.0\n")
        config = parse_config(
            f"version: 1\n{auth}server:\n  host: 0.0.0.0\n  allowed_hosts: [Warden.Example.com]\n"
        )
        assert config.server.allowed_hosts == ("warden.example.com",)

    def test_stdio_ignores_it(self, served_with: list[dict[str, Any]], tmp_path: Path) -> None:
        # The section is about HTTP: a stdio server has no port.
        policy = _policy(tmp_path, "server:\n  port: 9321\n")
        ran = []
        cli_module_server = type("S", (), {"run": lambda self, transport: ran.append(transport)})
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(cli_module, "create_server", lambda warden: cli_module_server())
            assert CliRunner().invoke(cli, ["--config", policy, "serve"]).exit_code == 0
        assert (ran, served_with) == (["stdio"], [])
