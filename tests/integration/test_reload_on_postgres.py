"""The policy against a real catalog that changes under it, and a real server reloading its
policy on a real SIGHUP."""

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from click.testing import CliRunner
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from psycopg.conninfo import make_conninfo

from sql_warden.auth import key_hash, new_api_key
from sql_warden.cli import DRIFTED, cli
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration

SETUP = """
    CREATE SCHEMA drift_test;
    CREATE TABLE drift_test.accounts (id int, email text, ssn text);
    INSERT INTO drift_test.accounts VALUES (1, 'a@example.com', '123-45-6789');
    CREATE TABLE drift_test.notes (id int, body text);
    CREATE ROLE dr_reader LOGIN PASSWORD 'dr_reader';
    GRANT USAGE ON SCHEMA drift_test TO dr_reader;
    GRANT SELECT ON drift_test.accounts, drift_test.notes TO dr_reader;
"""
TEARDOWN = """
    DROP SCHEMA drift_test CASCADE;
    DROP OWNED BY dr_reader;
    DROP ROLE dr_reader;
"""


@pytest.fixture
def drift_schema(warehouse: Warehouse) -> Iterator[Callable[[str], None]]:
    def admin(sql: str) -> None:
        with psycopg.connect(warehouse.admin_dsn, autocommit=True) as conn:
            conn.execute(sql)

    admin(SETUP)
    try:
        yield admin
    finally:
        admin(TEARDOWN)


def _drift_policy(warehouse: Warehouse, audit_dsn: str, path: Path) -> str:
    dsn = make_conninfo(warehouse.reader_dsn, user="dr_reader", password="dr_reader")
    path.write_text(
        "version: 1\n"
        f"warehouse:\n  dsn: {warehouse.reader_dsn}\n"
        # validate --live reads the file alone: without this it would look for the default
        # audit database, which only a machine running the demo stack has.
        f"audit:\n  dsn: '{audit_dsn}'\n"
        "default_profile: support\n"
        "profiles:\n"
        "  support:\n"
        f"    dsn: '{dsn}'\n"
        "    tables:\n"
        "      drift_test.accounts: '*'\n"
        "      drift_test.notes: [id, body]\n"
        "    masks:\n"
        "      drift_test.accounts.ssn: {strategy: redact}\n"
    )
    return str(path)


def _live(output: str) -> list[str]:
    """The profiles' part of `validate --live`: from its first line to the audit line, which
    is the shared test audit database's business, not this test's."""
    lines = output.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("  live:"))
    end = next(i for i, line in enumerate(lines) if line.startswith("  audit:     ") and i > start)
    return lines[start:end]


def test_catalog_drift(
    warehouse: Warehouse, audit_dsn: str, drift_schema: Callable[[str], None], tmp_path: Path
) -> None:
    policy = _drift_policy(warehouse, audit_dsn, tmp_path / "warden.yaml")

    def validate() -> Any:
        return CliRunner().invoke(cli, ["config", "validate", policy, "--live"])

    fits = validate()
    assert fits.exit_code == 0, fits.output
    assert _live(fits.output) == ["  live:      support: role dr_reader can only read"]

    # A migration renames the masked column, drops one the profile lists, and the role loses
    # a grant.
    drift_schema(
        "ALTER TABLE drift_test.accounts RENAME COLUMN ssn TO social_security_number;"
        "ALTER TABLE drift_test.notes DROP COLUMN body;"
    )
    columns_gone = validate()
    assert columns_gone.exit_code == 1
    assert _live(columns_gone.output) == [
        "  live:      support: role dr_reader can only read",
        "               ✗ the profile allows what the role can't see:",
        "                 column body of drift_test.notes",
        "               ✗ the profile masks columns the role can't see:",
        "                 drift_test.accounts.ssn",
    ]
    assert columns_gone.output.splitlines()[-1] == f"Error: {DRIFTED}"
    # Which is why: the column under its new name is read unmasked.
    ran = CliRunner().invoke(
        cli,
        ["--config", policy, "query", "select social_security_number from drift_test.accounts"],
    )
    assert ran.exit_code == 0, ran.output
    assert "123-45-6789" in ran.output

    drift_schema("REVOKE SELECT ON drift_test.notes FROM dr_reader")
    revoked = validate()
    assert revoked.exit_code == 1
    assert "                 table drift_test.notes" in revoked.output.splitlines()


FIRST_KEY, SECOND_KEY = new_api_key(), new_api_key()
SERVE = (sys.executable, "-m", "sql_warden")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _served_policy(warehouse: Warehouse, audit_dsn: str, port: int, key: tuple[str, str]) -> str:
    name, token = key
    return (
        "version: 1\n"
        f"warehouse:\n  dsn: '{warehouse.reader_dsn}'\n"
        f"audit:\n  dsn: '{audit_dsn}'\n"
        f"server:\n  port: {port}\n"
        "profiles:\n"
        f"  public:\n    dsn: '{warehouse.public_dsn}'\n"
        "    tables:\n      public.products: [id, name, price_cents]\n"
        "  admin:\n    tables: '*'\n"
        "auth:\n  api_keys:\n"
        f"    - {{name: {name}, profile: public, sha256: {key_hash(token)}}}\n"
    )


def _status(url: str, token: str) -> int:
    """What /mcp answers token: 401 if it isn't let in, something else if it is."""
    request = urllib.request.Request(
        url,
        data=json.dumps({}).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return exc.code


def _until(what: Callable[[], bool], why: str, timeout_s: float = 30) -> None:
    deadline = time.monotonic() + timeout_s
    while not what():
        assert time.monotonic() < deadline, why
        time.sleep(0.1)


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_a_running_server_reloads_on_sighup(
    warehouse: Warehouse, audit_dsn: str, tmp_path: Path, anyio_backend: str
) -> None:
    port = _free_port()
    policy = tmp_path / "warden.yaml"
    policy.write_text(_served_policy(warehouse, audit_dsn, port, ("first", FIRST_KEY)))
    log = tmp_path / "stderr.log"
    url = f"http://127.0.0.1:{port}/mcp"
    with log.open("w") as stderr:
        server = subprocess.Popen(
            [*SERVE, "--config", str(policy), "serve", "--transport", "http"],
            stdout=subprocess.DEVNULL,
            stderr=stderr,
            env={k: v for k, v in os.environ.items() if not k.startswith("SQL_WARDEN_")},
        )
    try:

        def answering() -> bool:
            assert server.poll() is None, log.read_text()
            try:
                return _status(url, FIRST_KEY) != 401
            except OSError:
                return False

        _until(answering, "the server never answered")
        assert _status(url, SECOND_KEY) == 401

        # The first key is revoked and a second issued, and the server told.
        policy.write_text(_served_policy(warehouse, audit_dsn, port, ("second", SECOND_KEY)))
        server.send_signal(signal.SIGHUP)
        _until(lambda: _status(url, SECOND_KEY) != 401, "the new key was never let in")
        assert _status(url, FIRST_KEY) == 401
        http = create_mcp_http_client(headers={"Authorization": f"Bearer {SECOND_KEY}"})
        async with http, Client(streamable_http_client(url, http_client=http)) as client:
            result: Any = await client.call_tool(
                "run_query", {"sql": "select count(*) from products"}
            )
        assert result.structured_content["result"]["rows"] == [[200]]

        # A broken file is refused, and the policy it would have replaced still served.
        policy.write_text("version: 1\nprofiles: [\n")
        server.send_signal(signal.SIGHUP)
        _until(lambda: "could not reload" in log.read_text(), "the failed reload wasn't logged")
        assert _status(url, SECOND_KEY) != 401
        assert server.poll() is None
    finally:
        server.terminate()
        server.wait(timeout=30)
    lines = log.read_text().splitlines()
    assert f"reloaded {policy}: serving profiles public, admin" in lines
    assert any(
        line.startswith(f"could not reload {policy}, so the policy loaded before is still served")
        for line in lines
    )
    assert "warden_reader:warden_reader" not in log.read_text()
