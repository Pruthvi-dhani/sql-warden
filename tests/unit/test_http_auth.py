"""The HTTP server behind tokens: one server for every profile, each request answered as
its token's caller. Over a real local HTTP server, with API keys and OIDC tokens.
"""

import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from click.testing import CliRunner
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from sql_warden import cli as cli_module
from sql_warden.audit import AuditError, AuditEvent, MemoryAuditSink
from sql_warden.auth import Authenticator, key_hash, new_api_key
from sql_warden.cli import ONLY_READERS, cli
from sql_warden.config import AuthConfig, BudgetConfig, IdentityBudgetConfig
from sql_warden.engines import Column, RoleReport, Table
from sql_warden.profiles import Access
from sql_warden.server import create_http_app
from sql_warden.warden import Warden
from tests.support import serving
from tests.unit.conftest import PRODUCTS, AuditSinks, FakeEngine
from tests.unit.test_auth import AUDIENCE, ISSUER, JWKS_URL, Provider, _token

pytestmark = pytest.mark.anyio

SALARIES = Table("public", "employee_salaries", (Column("id", "integer"),))
CATALOG = (PRODUCTS, SALARIES)
PUBLIC_KEY = new_api_key()
ADMIN_KEY = new_api_key()
OTHER_PUBLIC_KEY = new_api_key()
HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
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


AUTH = AuthConfig.model_validate(
    {
        "api_keys": [
            {"name": "web-agent", "profile": "public", "sha256": key_hash(PUBLIC_KEY)},
            {"name": "ops", "profile": "admin", "sha256": key_hash(ADMIN_KEY)},
            {"name": "web-agent-2", "profile": "public", "sha256": key_hash(OTHER_PUBLIC_KEY)},
        ],
        "oidc": {"issuer": ISSUER, "audience": AUDIENCE, "jwks_url": JWKS_URL},
    }
)


class Served:
    """Two profiles behind one server, sharing one audit log."""

    def __init__(self, provider: Provider | None = None, **warden: Any) -> None:
        self.audit = MemoryAuditSink()
        self.engines = {"public": FakeEngine(catalog=CATALOG), "admin": FakeEngine(catalog=CATALOG)}
        accesses = {"public": Access({("public", "products"): "*"}), "admin": Access("*")}
        self.wardens = {
            name: Warden(engine, audit=self.audit, profile=name, access=accesses[name], **warden)
            for name, engine in self.engines.items()
        }
        self.provider = provider or Provider()
        self.authenticator = Authenticator(
            AUTH, list(self.wardens), fetch=self.provider.fetch, clock=self.provider.clock
        )

    @property
    def events(self) -> list[AuditEvent]:
        return list(self.audit.events)

    def executed(self) -> list[str]:
        return [sql for engine in self.engines.values() for sql in engine.executed]


@contextmanager
def _served(served: Served, **settings: Any) -> Iterator[str]:
    app = create_http_app(served.wardens, authenticator=served.authenticator, **settings)
    with serving(app) as base_url:
        yield f"{base_url}/mcp"


@asynccontextmanager
async def _client(url: str, token: str, *, mode: str = "auto") -> Any:
    http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
    async with http, Client(streamable_http_client(url, http_client=http), mode=mode) as client:
        yield client


def _post(
    url: str, body: object = INITIALIZE, *, token: str | None = None, **headers: str
) -> tuple[int, dict[str, str], dict[str, Any]]:
    """POST body; the status, lower-cased headers, and the body if it is JSON."""
    sent = {**HEADERS, **headers}
    if token is not None:
        sent["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=sent, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw, status, got = response.read(), response.status, response.headers
    except urllib.error.HTTPError as exc:
        raw, status, got = exc.read(), exc.code, exc.headers
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = {}
    return status, {k.lower(): v for k, v in got.items()}, payload


def _structured(result: Any) -> dict[str, Any]:
    assert result.structured_content is not None
    content: dict[str, Any] = result.structured_content
    return content


class TestTurnedAway:
    def test_no_token(self) -> None:
        served = Served()
        with _served(served) as url:
            status, headers, body = _post(url, **{"User-Agent": "curl/8"})
        assert status == 401
        assert headers["www-authenticate"] == 'Bearer realm="sql-warden"'
        assert body == {
            "error": "invalid_token",
            "error_description": "this server needs a token: send Authorization: Bearer <token>",
            "code": "UNAUTHENTICATED",
        }
        # Recorded, with nothing run and no profile given.
        (event,) = served.events
        assert (event.profile, event.identity, event.decision, event.refused_by, event.code) == (
            None,
            None,
            "refused",
            "auth",
            "UNAUTHENTICATED",
        )
        assert (event.sql, event.client) == ("", "curl/8")
        assert served.executed() == []

    @pytest.mark.parametrize(
        "authorization",
        ["Bearer swk_not-a-key", "Bearer", "Basic dXNlcjpwYXNz", f"Token {PUBLIC_KEY}"],
    )
    def test_not_a_valid_one(self, authorization: str) -> None:
        served = Served()
        with _served(served) as url:
            status, headers, body = _post(url, Authorization=authorization)
        assert status == 401
        assert body["code"] == "UNAUTHENTICATED"
        assert headers["www-authenticate"].startswith('Bearer realm="sql-warden"')
        assert served.events[0].code == "UNAUTHENTICATED"

    def test_an_invalid_token_is_told_why(self) -> None:
        served = Served()
        with _served(served) as url:
            status, headers, _ = _post(url, token=_token(aud="another-service"))
        assert status == 401
        assert headers["www-authenticate"] == (
            'Bearer realm="sql-warden", error="invalid_token", '
            'error_description="the token is for another service"'
        )

    def test_a_valid_token_that_gives_no_profile(self) -> None:
        served = Served()
        with _served(served) as url:
            status, headers, body = _post(url, token=_token(sql_warden_profile="support"))
        assert status == 403
        assert body["code"] == "NO_PROFILE"
        assert 'error="insufficient_scope"' in headers["www-authenticate"]
        # A real caller: recorded under their name, still with no profile.
        (event,) = served.events
        assert (event.identity, event.profile, event.code) == ("oidc:user-42", None, "NO_PROFILE")

    def test_when_the_provider_cant_be_asked(self) -> None:
        served = Served(Provider(down=True))
        with _served(served) as url:
            status, headers, body = _post(url, token=_token())
            # An API key needs no provider, so it still gets in.
            assert _post(url, token=PUBLIC_KEY)[0] == 200
        assert (status, body["code"]) == (503, "AUTH_UNAVAILABLE")
        assert headers["retry-after"] == "60"
        assert "www-authenticate" not in headers

    def test_a_refusal_that_cant_be_recorded_is_still_a_refusal(self) -> None:
        served = Served()
        served.audit.fail_with = AuditError("down")
        with _served(served) as url:
            assert _post(url)[0] == 401

    def test_every_method(self) -> None:
        served = Served()
        with _served(served) as url:
            for method in ("GET", "DELETE", "PUT"):
                request = urllib.request.Request(url, method=method, headers=HEADERS)
                with pytest.raises(urllib.error.HTTPError) as excinfo:
                    urllib.request.urlopen(request, timeout=10)
                assert excinfo.value.code == 401


class TestOneServerEveryProfile:
    async def test_each_token_sees_its_own_profiles_tables(self) -> None:
        served = Served()
        with _served(served) as url:
            async with _client(url, PUBLIC_KEY) as public, _client(url, ADMIN_KEY) as admin:
                seen = {
                    "public": _structured(await public.call_tool("list_tables", {})),
                    "admin": _structured(await admin.call_tool("list_tables", {})),
                }
        assert {name: answer["profile"] for name, answer in seen.items()} == {
            "public": "public",
            "admin": "admin",
        }
        assert [t["name"] for t in seen["public"]["tables"]] == ["products"]
        assert [t["name"] for t in seen["admin"]["tables"]] == ["products", "employee_salaries"]

    async def test_the_same_query_gets_each_its_own_decision(self) -> None:
        served = Served()
        sql = "select count(*) from employee_salaries"
        with _served(served) as url:
            async with _client(url, PUBLIC_KEY) as public, _client(url, ADMIN_KEY) as admin:
                refused = await public.call_tool("run_query", {"sql": sql})
                allowed = await admin.call_tool("run_query", {"sql": sql})
        assert refused.is_error is True
        assert _structured(refused)["code"] == "TABLE_NOT_ALLOWED"
        assert allowed.is_error is False
        # Run by the admin profile's engine, and nothing by the public one's.
        assert served.engines["public"].executed == []
        assert served.engines["admin"].executed == [
            "SELECT COUNT(*) FROM public.employee_salaries LIMIT 101"
        ]
        recorded = [(e.identity, e.profile, e.decision) for e in served.events]
        assert recorded == [("web-agent", "public", "refused"), ("ops", "admin", "allowed")]

    async def test_an_oidc_caller(self) -> None:
        served = Served()
        with _served(served) as url:
            async with _client(url, _token(sql_warden_profile="admin", sub="ana")) as client:
                result = _structured(await client.call_tool("check_query", {"sql": "select 1"}))
        assert result["profile"] == "admin"
        assert served.events[0].identity == "oidc:ana"

    async def test_the_instructions_dont_name_a_profile(self) -> None:
        served = Served()
        with _served(served) as url:
            async with _client(url, PUBLIC_KEY, mode="legacy") as client:
                instructions = client.session.initialize_result.instructions
        assert instructions is not None
        assert "comes from your token" in instructions
        assert "'public' profile" not in instructions


class TestSessions:
    async def test_a_caller_without_connections_is_one_session(self) -> None:
        served = Served()
        with _served(served) as url:
            async with (
                _client(url, PUBLIC_KEY) as first,
                _client(url, PUBLIC_KEY) as again,
                _client(url, OTHER_PUBLIC_KEY) as other,
            ):
                one = _structured(await first.call_tool("check_query", {"sql": "select 1"}))
                two = _structured(await again.call_tool("check_query", {"sql": "select 1"}))
                three = _structured(await other.call_tool("check_query", {"sql": "select 1"}))
        # The same caller, whatever client it uses; another caller, another session.
        assert one["session_id"] == two["session_id"]
        assert three["session_id"] != one["session_id"]
        assert served.wardens["public"].session_id not in {one["session_id"], three["session_id"]}

    async def test_so_one_callers_budget_is_not_anothers(self) -> None:
        served = Served(budget=BudgetConfig(max_queries=1))
        with _served(served) as url:
            async with _client(url, PUBLIC_KEY) as one, _client(url, OTHER_PUBLIC_KEY) as other:
                await one.call_tool("run_query", {"sql": "select 1"})
                spent = _structured(await one.call_tool("run_query", {"sql": "select 1"}))
                fresh = await other.call_tool("run_query", {"sql": "select 1"})
        assert spent["code"] == "BUDGET_EXHAUSTED"
        assert fresh.is_error is False

    async def test_reconnecting_doesnt_start_a_fresh_caller_budget(self) -> None:
        served = Served(identity_budget=IdentityBudgetConfig(max_queries=1))
        with _served(served) as url:
            async with _client(url, PUBLIC_KEY, mode="legacy") as first:
                ran = _structured(await first.call_tool("run_query", {"sql": "select 1"}))
            # A new connection is a new session...
            async with _client(url, PUBLIC_KEY, mode="legacy") as again:
                refused = _structured(await again.call_tool("run_query", {"sql": "select 1"}))
            # ...and another caller is not held to this one's budget.
            async with _client(url, OTHER_PUBLIC_KEY, mode="legacy") as other:
                fresh = await other.call_tool("run_query", {"sql": "select 1"})
        assert refused["session_id"] != ran["session_id"]
        assert refused["code"] == "BUDGET_EXHAUSTED"
        assert refused["reason"].startswith("web-agent's budget for any 24 hours is used up")
        assert refused["budget"]["caller"]["exhausted"] == "max_queries"
        assert fresh.is_error is False

    async def test_a_connection_is_its_callers_alone(self) -> None:
        served = Served()
        with _served(served) as url:
            status, headers, _ = _post(url, token=PUBLIC_KEY)
            assert status == 200
            connection = headers["mcp-session-id"]
            call = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "check_query", "arguments": {"sql": "select 1"}},
            }
            # Another caller holding the connection's id gets nothing from it, as though it
            # didn't exist: not even with a key for the same profile.
            for token in (OTHER_PUBLIC_KEY, ADMIN_KEY):
                assert _post(url, call, token=token, **{"Mcp-Session-Id": connection})[0] == 404
            assert _post(url, call, token=PUBLIC_KEY, **{"Mcp-Session-Id": connection})[0] == 200
        assert [e.identity for e in served.events] == ["web-agent"]


class TestWhereItListens:
    def test_beyond_loopback_with_the_names_it_is_reached_by(self) -> None:
        served = Served()
        app = create_http_app(
            served.wardens,
            host="0.0.0.0",
            authenticator=served.authenticator,
            allowed_hosts=["warden.example.com"],
        )
        with serving(app) as base_url:
            url = f"{base_url}/mcp"
            port = base_url.rsplit(":", 1)[1]
            assert _post(url, token=PUBLIC_KEY, Host="warden.example.com")[0] == 200
            assert _post(url, token=PUBLIC_KEY, Host=f"warden.example.com:{port}")[0] == 200
            assert _post(url, token=PUBLIC_KEY, Host="evil.example")[0] == 421

    def test_pages_from_listed_origins_only(self) -> None:
        served = Served()
        with _served(served, allowed_origins=["https://portal.example.com"]) as url:
            listed = _post(url, token=PUBLIC_KEY, Origin="https://portal.example.com")
            other = _post(url, token=PUBLIC_KEY, Origin="https://evil.example")
        assert (listed[0], other[0]) == (200, 403)

    def test_beyond_loopback_without_the_names_is_refused(self) -> None:
        served = Served()
        with pytest.raises(ValueError, match="give allowed_hosts"):
            create_http_app(served.wardens, host="0.0.0.0", authenticator=served.authenticator)

    def test_without_authentication_it_is_still_one_profile_on_loopback(self) -> None:
        served = Served()
        with pytest.raises(ValueError, match="serving more than one profile needs authentication"):
            create_http_app(served.wardens)
        warden = served.wardens["public"]
        with pytest.raises(ValueError, match="only listens on loopback"):
            create_http_app(warden, host="0.0.0.0")
        with pytest.raises(ValueError, match="come with authentication"):
            create_http_app(warden, allowed_hosts=["warden.example.com"])


POLICY = f"""
version: 1
warehouse:
  dsn: postgresql://warden_reader:hunter2@db.internal/warehouse
default_profile: public
profiles:
  public:
    dsn: postgresql://warden_public:hunter3@db.internal/warehouse
    tables:
      public.products: "*"
  admin:
    tables: "*"
auth:
  api_keys:
    - {{name: web-agent, profile: public, sha256: {key_hash(PUBLIC_KEY)}}}
"""


@pytest.fixture
def policy(tmp_path: Path) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY)
    return str(path)


@pytest.fixture
def listening(monkeypatch: pytest.MonkeyPatch, audit_sinks: AuditSinks) -> list[dict[str, Any]]:
    """Stands in for uvicorn, and collects what `serve` would have run it with."""
    runs: list[dict[str, Any]] = []
    monkeypatch.setattr(
        uvicorn, "run", lambda app, **settings: runs.append({"app": app, **settings})
    )
    return runs


def _engines(monkeypatch: pytest.MonkeyPatch, **by_user: RoleReport) -> list[str]:
    built: list[str] = []

    def engine(dsn: str, **_: Any) -> FakeEngine:
        built.append(dsn.split("//")[1].split(":")[0])
        user = built[-1]
        # Each role can read what its profile may: so no warning that it reads more.
        catalog = (PRODUCTS,) if user == "warden_public" else CATALOG
        return FakeEngine(dsn, catalog=catalog, report=by_user.get(user, RoleReport(user)))

    monkeypatch.setattr(cli_module, "PostgresEngine", engine)
    return built


class TestServe:
    def test_it_serves_every_profile_and_checks_every_role(
        self, policy: str, listening: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = _engines(monkeypatch)
        outcome = CliRunner().invoke(cli, ["--config", policy, "serve", "--transport", "http"])
        assert outcome.exit_code == 0, outcome.output
        assert built == ["warden_public", "warden_reader"]
        assert outcome.stderr.splitlines()[-1] == (
            "sql-warden MCP server on http://127.0.0.1:8000/mcp, profiles public, admin, to "
            "callers with a token (Ctrl+C stops it)"
        )
        assert len(listening) == 1

    def test_not_when_one_profiles_role_can_write(
        self, policy: str, listening: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _engines(monkeypatch, warden_reader=RoleReport("warden_reader", ("is a superuser",)))
        outcome = CliRunner().invoke(cli, ["--config", policy, "serve", "--transport", "http"])
        assert outcome.exit_code == 1
        assert outcome.output.splitlines()[:2] == [
            "Error: profile admin: role warden_reader can change the warehouse "
            "(db.internal/warehouse as warden_reader):",
            "  it is a superuser",
        ]
        assert outcome.output.splitlines()[-1] == ONLY_READERS
        assert listening == []

    def test_the_profile_flag_is_for_stdio(
        self, policy: str, listening: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _engines(monkeypatch)
        outcome = CliRunner().invoke(
            cli, ["--config", policy, "serve", "--transport", "http", "--profile", "admin"]
        )
        assert outcome.exit_code == 1
        assert "--profile is for stdio" in outcome.output
        assert listening == []
        # Over stdio it picks the profile as ever.
        stdio = []
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(
                cli_module,
                "create_server",
                lambda warden: type("S", (), {"run": lambda self, t: stdio.append(warden)})(),
            )
            ran = CliRunner().invoke(cli, ["--config", policy, "serve", "--profile", "admin"])
        assert ran.exit_code == 0, ran.output
        assert [warden.profile for warden in stdio] == ["admin"]

    def test_beyond_loopback_it_warns_about_tls(
        self,
        tmp_path: Path,
        listening: list[dict[str, Any]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _engines(monkeypatch)
        path = tmp_path / "policy.yaml"
        path.write_text(
            POLICY + "server:\n  host: 0.0.0.0\n  allowed_hosts: [warden.example.com]\n"
        )
        outcome = CliRunner().invoke(cli, ["--config", str(path), "serve", "--transport", "http"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.stderr.splitlines()[0].startswith(
            "warning: serving plain HTTP on 0.0.0.0. Every request carries its token"
        )
        (run,) = listening
        assert (run["host"], run["port"]) == ("0.0.0.0", 8000)

    def test_validate_describes_it(self, policy: str) -> None:
        outcome = CliRunner().invoke(cli, ["config", "validate", policy])
        assert outcome.exit_code == 0, outcome.output
        assert "  auth:      1 API key: web-agent → public" in outcome.output.splitlines()
        assert key_hash(PUBLIC_KEY) not in outcome.output

    def test_validate_without_auth_says_so(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.yaml"
        path.write_text("version: 1\n")
        outcome = CliRunner().invoke(cli, ["config", "validate", str(path)])
        assert (
            "  auth:      none: HTTP needs no token, and is served on loopback only"
            in outcome.output.splitlines()
        )


class TestNewKey:
    def test_it_prints_the_key_once_and_the_entry_with_its_hash(self, policy: str) -> None:
        outcome = CliRunner().invoke(
            cli, ["--config", policy, "auth", "new-key", "nightly-report", "--profile", "admin"]
        )
        assert outcome.exit_code == 0, outcome.output
        lines = outcome.output.splitlines()
        key = lines[0].removeprefix("key: ")
        assert key.startswith("swk_")
        assert lines[-3:] == [
            "  - name: nightly-report",
            "    profile: admin",
            f"    sha256: {key_hash(key)}",
        ]
        # The key works as soon as the entry is in the config.
        auth = AuthConfig.model_validate(
            {"api_keys": [{"name": "nightly-report", "profile": "admin", "sha256": key_hash(key)}]}
        )
        assert Authenticator(auth, ["admin"]).authenticate(key).name == "nightly-report"

    @pytest.mark.parametrize(
        ("args", "problem"),
        [
            (["bot", "--profile", "root"], "unknown profile 'root': "),
            (["web-agent", "--profile", "public"], "already has a key named web-agent"),
            (["a b", "--profile", "public"], "key name 'a b': a key's name is up to 64"),
        ],
    )
    def test_problems(self, policy: str, args: list[str], problem: str) -> None:
        outcome = CliRunner().invoke(cli, ["--config", policy, "auth", "new-key", *args])
        assert outcome.exit_code == 1
        assert problem in outcome.output
        assert "swk_" not in outcome.output

    def test_it_needs_profiles(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.yaml"
        path.write_text("version: 1\n")
        outcome = CliRunner().invoke(
            cli, ["--config", str(path), "auth", "new-key", "bot", "--profile", "all"]
        )
        assert outcome.exit_code == 1
        assert "defines no profiles" in outcome.output
