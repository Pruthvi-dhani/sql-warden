"""One HTTP server for every profile, against the seeded warehouse and a real audit log:
the public key's requests run as warden_public, the admin key's as warden_reader, and the
audit log says which caller asked what.
"""

import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from sql_warden.auth import Authenticator, key_hash, new_api_key
from sql_warden.cli import build_warden, cli, open_audit
from sql_warden.config import load_config
from sql_warden.server import create_http_app
from tests.integration.conftest import Warehouse
from tests.support import serving

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

PUBLIC_KEY = new_api_key()
ADMIN_KEY = new_api_key()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def policy(warehouse: Warehouse, audit_dsn: str, tmp_path: Path) -> Path:
    path = tmp_path / "warden.yaml"
    path.write_text(
        f"version: 1\nwarehouse:\n  dsn: {warehouse.reader_dsn}\n"
        f"audit:\n  dsn: {audit_dsn}\n"
        "profiles:\n"
        f"  public:\n    dsn: {warehouse.public_dsn}\n"
        "    tables:\n      public.products: [id, name, price_cents]\n"
        '  admin:\n    tables: "*"\n'
        "auth:\n  api_keys:\n"
        f"    - {{name: web-agent, profile: public, sha256: {key_hash(PUBLIC_KEY)}}}\n"
        f"    - {{name: ops, profile: admin, sha256: {key_hash(ADMIN_KEY)}}}\n"
    )
    return path


@pytest.fixture
def url(policy: Path) -> Iterator[str]:
    """The server `serve --transport http` builds from the policy."""
    config = load_config(policy)
    assert config.auth is not None
    profiles = list(config.profiles or {})
    audit = open_audit(config)
    wardens = {name: build_warden(config, name, audit=audit, serving=True) for name in profiles}
    app = create_http_app(wardens, authenticator=Authenticator(config.auth, profiles))
    with serving(app) as base_url:
        yield f"{base_url}/mcp"
    audit.close()


async def _call(url: str, key: str, tool: str, **arguments: Any) -> Any:
    http = create_mcp_http_client(headers={"Authorization": f"Bearer {key}"})
    async with http, Client(streamable_http_client(url, http_client=http)) as client:
        return await client.call_tool(tool, arguments)


def _structured(result: Any) -> dict[str, Any]:
    assert result.structured_content is not None
    content: dict[str, Any] = result.structured_content
    return content


async def test_each_key_reads_as_its_own_profile(url: str) -> None:
    sql = "select count(*) as n from employee_salaries"
    public = await _call(url, PUBLIC_KEY, "run_query", sql=sql)
    admin = await _call(url, ADMIN_KEY, "run_query", sql=sql)
    assert _structured(public)["code"] == "TABLE_NOT_ALLOWED"
    assert _structured(admin)["result"]["rows"] == [[50]]
    tables = await _call(url, PUBLIC_KEY, "list_tables")
    assert [t["name"] for t in _structured(tables)["tables"]] == ["products"]


async def test_the_audit_log_says_who_asked(url: str, policy: Path) -> None:
    await _call(url, ADMIN_KEY, "check_query", sql="select 1 as who_asked")
    request = urllib.request.Request(url, data=b"{}", method="POST")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(request, timeout=10)
    assert excinfo.value.code == 401

    runner = CliRunner()
    mine = runner.invoke(
        cli, ["--config", str(policy), "audit", "tail", "--identity", "ops", "--json"]
    )
    events = [json.loads(line) for line in mine.output.splitlines()]
    assert events[-1]["sql"] == "select 1 as who_asked"
    assert {(e["identity"], e["profile"]) for e in events} == {("ops", "admin")}

    refused = runner.invoke(
        cli,
        ["--config", str(policy), "audit", "tail", "--decision", "refused", "-n", "1", "--json"],
    )
    (turned_away,) = [json.loads(line) for line in refused.output.splitlines()]
    assert (turned_away["refused_by"], turned_away["code"], turned_away["profile"]) == (
        "auth",
        "UNAUTHENTICATED",
        None,
    )
    shown = runner.invoke(cli, ["--config", str(policy), "audit", "show", turned_away["id"]])
    assert "profile  -" in shown.output.splitlines()
