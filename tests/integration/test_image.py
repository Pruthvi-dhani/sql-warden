"""The container image: built from this repository's Dockerfile, run against the warehouse
and audit containers as it would be deployed, and asked what a load balancer, Prometheus
and an agent would ask it."""

import json
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from testcontainers.core.container import DockerContainer
from testcontainers.core.image import DockerImage

from sql_warden.auth import key_hash, new_api_key
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration

ROOT = Path(__file__).parents[2]
KEY = new_api_key()
CONFIG_PATH = "/etc/sql-warden/warden.yaml"


@pytest.fixture(scope="module")
def image() -> Iterator[str]:
    with DockerImage(path=ROOT, tag="sql-warden:integration-test", clean_up=True) as built:
        yield str(built)


@pytest.fixture(scope="module")
def config(
    warehouse: Warehouse, audit_internal_dsn: str, tmp_path_factory: pytest.TempPathFactory
) -> Path:
    path = tmp_path_factory.mktemp("image") / "warden.yaml"
    path.write_text(
        "version: 1\n"
        f"warehouse:\n  dsn: {warehouse.inside(warehouse.reader_dsn)}\n"
        f"audit:\n  dsn: {audit_internal_dsn}\n"
        "server:\n  allowed_hosts: [sql-warden.test]\n"
        "profiles:\n"
        f"  public:\n    dsn: {warehouse.inside(warehouse.public_dsn)}\n"
        "    tables:\n      public.products: [id, name, price_cents]\n"
        "auth:\n  api_keys:\n"
        f"    - {{name: image-test, profile: public, sha256: {key_hash(KEY)}}}\n"
    )
    path.chmod(0o644)  # read by the image's own user, not this one
    return path


def _started(image: str, config: Path) -> DockerContainer:
    container = (
        DockerContainer(image)
        .with_volume_mapping(str(config), CONFIG_PATH, "ro")
        .with_exposed_ports(8000)
    )
    container.start()
    deadline = time.monotonic() + 60
    while True:
        try:
            if _get(_url(container, "/healthz"))[0] == 200:
                return container
        except OSError:
            pass
        if time.monotonic() > deadline:
            logs = container.get_logs()
            container.stop()
            raise AssertionError(f"the image never answered /healthz: {logs!r}")
        time.sleep(0.5)


@pytest.fixture(scope="module")
def running(image: str, config: Path) -> Iterator[DockerContainer]:
    container = _started(image, config)
    yield container
    container.stop()


def _url(container: DockerContainer, path: str) -> str:
    host = container.get_container_host_ip()
    return f"http://{host}:{container.get_exposed_port(8000)}{path}"


def _get(url: str, **headers: str) -> tuple[int, str]:
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_it_runs_as_its_own_unprivileged_user(running: DockerContainer) -> None:
    code, output = running.exec(["id", "-u"])
    assert (code, output.decode().strip()) == (0, "10001")


def test_health_and_readiness(running: DockerContainer) -> None:
    assert _get(_url(running, "/healthz")) == (200, "ok\n")
    status, body = _get(_url(running, "/readyz"))
    assert (status, json.loads(body)) == (200, {"ready": True, "failing": []})


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
async def test_an_agent_with_a_token_is_answered(
    running: DockerContainer, anyio_backend: str
) -> None:
    http = create_mcp_http_client(headers={"Authorization": f"Bearer {KEY}"})
    async with http, Client(streamable_http_client(_url(running, "/mcp"), http_client=http)) as c:
        result: Any = await c.call_tool("run_query", {"sql": "select count(*) as n from products"})
        refused: Any = await c.call_tool("run_query", {"sql": "select * from employee_salaries"})
    assert result.structured_content["result"]["rows"] == [[200]]
    assert refused.structured_content["code"] == "TABLE_NOT_ALLOWED"
    # Without a token, nothing.
    request = urllib.request.Request(_url(running, "/mcp"), data=b"{}", method="POST")
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(request, timeout=10)
    assert excinfo.value.code == 401
    # And Prometheus sees all three.
    status, metrics = _get(_url(running, "/metrics"))
    assert status == 200
    lines = metrics.splitlines()
    assert 'sql_warden_requests_total{profile="public",kind="query",decision="allowed"} 1' in lines
    assert (
        'sql_warden_refusals_total{profile="public",check="access",code="TABLE_NOT_ALLOWED"} 1'
        in lines
    )
    assert 'sql_warden_auth_refusals_total{code="UNAUTHENTICATED"} 1' in lines


def test_it_stops_cleanly_on_sigterm(image: str, config: Path) -> None:
    container = _started(image, config)
    wrapped = container.get_wrapped_container()
    started = time.monotonic()
    wrapped.stop(timeout=20)  # SIGTERM, then SIGKILL after 20 s
    wrapped.reload()
    assert wrapped.attrs["State"]["ExitCode"] == 0
    assert time.monotonic() - started < 15
    wrapped.remove()
