"""What a running server says about itself: /metrics for Prometheus, /healthz and /readyz
for whatever runs it."""

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import anyio.to_thread
import pytest
import uvicorn
from click.testing import CliRunner

from sql_warden import cli as cli_module
from sql_warden.audit import AuditError, MemoryAuditSink
from sql_warden.auth import Authenticator, key_hash, new_api_key
from sql_warden.cli import cli
from sql_warden.config import AuthConfig, ConfigError, parse_config
from sql_warden.engines import CostEstimate, QueryFailed, RoleReport
from sql_warden.metrics import CONTENT_TYPE, Counter, Gauge, Histogram, Metrics
from sql_warden.profiles import Access
from sql_warden.server import Readiness, create_http_app
from sql_warden.warden import Warden
from tests.support import serving
from tests.unit.conftest import AuditSinks, FakeEngine


def _warden(metrics: Metrics, engine: FakeEngine | None = None, **settings: Any) -> Warden:
    return Warden(engine or FakeEngine(), audit=MemoryAuditSink(), metrics=metrics, **settings)


class TestTheFormat:
    def test_a_counter(self) -> None:
        counter = Counter("things_total", "Things.", ("kind",))
        counter.inc(kind="a")
        counter.inc(2, kind="b")
        counter.inc(kind="a")
        assert counter.header() + counter.lines() == [
            "# HELP things_total Things.",
            "# TYPE things_total counter",
            'things_total{kind="a"} 2',
            'things_total{kind="b"} 2',
        ]
        with pytest.raises(ValueError, match="only goes up"):
            counter.inc(-1, kind="a")
        with pytest.raises(ValueError, match="takes the labels kind"):
            counter.inc(other="x")

    def test_one_without_labels_starts_at_zero(self) -> None:
        assert Counter("failures_total", "F.").lines() == ["failures_total 0"]

    def test_label_values_are_escaped(self) -> None:
        counter = Counter("c_total", "C.", ("v",))
        counter.inc(v='a"b\\c\nd')
        assert counter.lines() == ['c_total{v="a\\"b\\\\c\\nd"} 1']

    def test_a_gauge(self) -> None:
        gauge = Gauge("busy", "Busy.")
        gauge.add(2)
        gauge.add(-1)
        assert gauge.lines() == ["busy 1"]

    def test_a_histogram_is_cumulative(self) -> None:
        histogram = Histogram("t_seconds", "T.", ("p",), (0.1, 1))
        for value in (0.05, 0.5, 0.5, 5):
            histogram.observe(value, p="x")
        assert histogram.lines() == [
            't_seconds_bucket{p="x",le="0.1"} 1',
            't_seconds_bucket{p="x",le="1"} 3',
            't_seconds_bucket{p="x",le="+Inf"} 4',
            't_seconds_sum{p="x"} 6.05',
            't_seconds_count{p="x"} 4',
        ]


class TestWhatIsCounted:
    def test_allowed_refused_and_failed(self) -> None:
        metrics = Metrics()
        warden = _warden(metrics, profile="public")
        warden.run("select 1")
        warden.check("select 1")
        warden.run("select 1; select 2")
        failing = _warden(metrics, FakeEngine(error=QueryFailed("boom")), profile="public")
        failing.run("select 1")
        requests = metrics.requests
        assert requests.value(profile="public", kind="query", decision="allowed") == 1
        assert requests.value(profile="public", kind="check", decision="allowed") == 1
        assert requests.value(profile="public", kind="query", decision="refused") == 1
        assert requests.value(profile="public", kind="query", decision="failed") == 1
        assert (
            metrics.refusals.value(profile="public", check="shape", code="MULTIPLE_STATEMENTS") == 1
        )
        assert metrics.duration.count(profile="public", kind="query") == 3
        assert metrics.rows.value(profile="public") == 1

    def test_estimated_costs(self) -> None:
        metrics = Metrics()
        estimate = CostEstimate(total_cost=2_500, est_rows=1, top_node="Seq Scan")
        _warden(metrics, FakeEngine(estimate=estimate)).run("select 1")
        assert metrics.cost.count(profile="all") == 1
        assert 'sql_warden_estimated_cost_bucket{profile="all",le="10000"} 1' in metrics.render()
        assert 'sql_warden_estimated_cost_bucket{profile="all",le="1000"} 0' in metrics.render()

    def test_an_audit_write_that_fails(self) -> None:
        metrics = Metrics()
        warden = _warden(metrics)
        assert isinstance(warden.audit, MemoryAuditSink)
        warden.audit.fail_with = AuditError("down")
        warden.run("select 1")
        warden.check("select 1")
        assert metrics.audit_failures.value() == 2
        refused = metrics.refusals.value(profile="all", check="audit", code="AUDIT_UNAVAILABLE")
        assert refused == 2

    def test_nothing_in_flight_once_answered(self) -> None:
        metrics = Metrics()
        seen = []

        class Watching(FakeEngine):
            def execute(self, sql: str, *, tag: str | None = None) -> Any:
                seen.append(metrics.in_flight.value)
                return super().execute(sql, tag=tag)

        _warden(metrics, Watching()).run("select 1")
        assert (seen, metrics.in_flight.value) == ([1], 0)

    def test_a_warden_without_metrics_counts_nothing(self) -> None:
        assert Warden(FakeEngine(), audit=MemoryAuditSink()).run("select 1").result is not None

    def test_the_whole_page(self) -> None:
        text = Metrics().render()
        assert text.endswith("\n")
        names = [line.split()[2] for line in text.splitlines() if line.startswith("# TYPE")]
        assert names == [
            "sql_warden_info",
            "sql_warden_requests_total",
            "sql_warden_refusals_total",
            "sql_warden_request_duration_seconds",
            "sql_warden_estimated_cost",
            "sql_warden_rows_returned_total",
            "sql_warden_audit_write_failures_total",
            "sql_warden_auth_refusals_total",
            "sql_warden_requests_in_flight",
        ]
        assert "sql_warden_info 1" in text.splitlines()


def _get(url: str) -> tuple[int, dict[str, str], str]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            return response.status, headers, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read().decode()


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class TestEndpoints:
    def test_healthz(self) -> None:
        with serving(create_http_app(Warden(FakeEngine(), audit=MemoryAuditSink()))) as url:
            status, headers, body = _get(f"{url}/healthz")
        assert (status, body, headers["cache-control"]) == (200, "ok\n", "no-store")

    def test_readyz_without_checks_is_ready(self) -> None:
        with serving(create_http_app(Warden(FakeEngine(), audit=MemoryAuditSink()))) as url:
            status, _, body = _get(f"{url}/readyz")
        assert (status, json.loads(body)) == (200, {"ready": True, "failing": []})

    def test_readyz_names_what_fails_and_nothing_more(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        def down() -> None:
            raise RuntimeError("could not connect to db.internal as warden_reader")

        readiness = Readiness({"audit": lambda: None, "warehouse:public": down})
        app = create_http_app(Warden(FakeEngine(), audit=MemoryAuditSink()), readiness=readiness)
        with serving(app) as url:
            status, _, body = _get(f"{url}/readyz")
        assert (status, json.loads(body)) == (
            503,
            {"ready": False, "failing": ["warehouse:public"]},
        )
        assert "db.internal" not in body  # the reason is logged, not sent
        assert "could not connect to db.internal" in caplog.text

    @pytest.mark.anyio
    @pytest.mark.parametrize("anyio_backend", ["asyncio"])
    async def test_readiness_is_reused_for_a_while(self, anyio_backend: str) -> None:
        asked = []
        clock = Clock()
        readiness = Readiness({"audit": lambda: asked.append(1)}, ready_for_s=10, clock=clock)
        await readiness.failing()
        clock.now += 9
        await readiness.failing()
        assert len(asked) == 1
        clock.now += 2
        await readiness.failing()
        assert len(asked) == 2

    @pytest.mark.anyio
    @pytest.mark.parametrize("anyio_backend", ["asyncio"])
    async def test_requests_answered_at_once_are_capped(self, anyio_backend: str) -> None:
        app = create_http_app(
            Warden(FakeEngine(), audit=MemoryAuditSink()), max_concurrent_requests=3
        )
        async with app.router.lifespan_context(app):
            # The threads tool calls are answered in: the rest wait for one to be free.
            assert anyio.to_thread.current_default_thread_limiter().total_tokens == 3

    def test_metrics_only_when_asked_for(self) -> None:
        warden = Warden(FakeEngine(), audit=MemoryAuditSink())
        with serving(create_http_app(warden)) as url:
            assert _get(f"{url}/metrics")[0] == 404
        metrics = Metrics()
        with serving(create_http_app(warden, metrics=metrics)) as url:
            status, headers, body = _get(f"{url}/metrics")
        assert (status, headers["content-type"]) == (200, CONTENT_TYPE)
        assert body == metrics.render()

    def test_none_of_them_need_a_token_and_auth_refusals_are_counted(self) -> None:
        key = new_api_key()
        auth = AuthConfig.model_validate(
            {"api_keys": [{"name": "bot", "profile": "public", "sha256": key_hash(key)}]}
        )
        metrics = Metrics()
        warden = Warden(FakeEngine(), audit=MemoryAuditSink(), profile="public", access=Access("*"))
        app = create_http_app(
            {"public": warden}, authenticator=Authenticator(auth, ["public"]), metrics=metrics
        )
        with serving(app) as url:
            assert [_get(f"{url}{path}")[0] for path in ("/healthz", "/readyz", "/metrics")] == [
                200,
                200,
                200,
            ]
            assert _get(f"{url}/mcp")[0] == 401
        assert metrics.auth_refusals.value(code="UNAUTHENTICATED") == 1


POLICY = """
version: 1
server:
  max_concurrent_requests: 4
  shutdown_grace_s: 12
"""


class TestServe:
    @pytest.fixture
    def listening(
        self, monkeypatch: pytest.MonkeyPatch, audit_sinks: AuditSinks
    ) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        monkeypatch.setattr(
            uvicorn, "run", lambda app, **settings: runs.append({"app": app, **settings})
        )
        monkeypatch.setattr(cli_module, "PostgresEngine", lambda dsn, **_: FakeEngine(dsn))
        return runs

    def test_it_serves_metrics_and_readiness_and_stops_gracefully(
        self, listening: list[dict[str, Any]], tmp_path: Path
    ) -> None:
        path = tmp_path / "warden.yaml"
        path.write_text(POLICY)
        outcome = CliRunner().invoke(cli, ["--config", str(path), "serve", "--transport", "http"])
        assert outcome.exit_code == 0, outcome.output
        (run,) = listening
        assert run["timeout_graceful_shutdown"] == 12
        with serving(run["app"]) as url:
            assert _get(f"{url}/readyz")[0] == 200
            assert _get(f"{url}/metrics")[0] == 200

    def test_readiness_fails_once_a_role_can_write(
        self, listening: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        engine = FakeEngine()
        monkeypatch.setattr(cli_module, "PostgresEngine", lambda dsn, **_: engine)
        assert CliRunner().invoke(cli, ["serve", "--transport", "http"]).exit_code == 0
        engine.report = RoleReport("fake_reader", ("can INSERT on public.orders",))
        with serving(listening[0]["app"]) as url:
            status, _, body = _get(f"{url}/readyz")
        assert (status, json.loads(body)["failing"]) == (503, ["warehouse:all"])

    @pytest.mark.parametrize(
        ("setting", "value"),
        [
            ("max_concurrent_requests", 0),
            ("max_concurrent_requests", 1001),
            ("shutdown_grace_s", -1),
        ],
    )
    def test_settings_out_of_range(self, setting: str, value: int) -> None:
        with pytest.raises(ConfigError, match=f"server.{setting}"):
            parse_config(f"version: 1\nserver:\n  {setting}: {value}\n")

    def test_the_defaults(self) -> None:
        server = parse_config("version: 1\n").server
        assert (server.max_concurrent_requests, server.shutdown_grace_s) == (32, 30)
