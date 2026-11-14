"""The warehouse's connection pool without a database: its config, which commands pool,
what /metrics says about it, and what an engine says when it can't get a connection. Against
Postgres in tests/integration/test_pool_on_postgres.py."""

import time
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sql_warden import cli as cli_module
from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import cli
from sql_warden.config import ConfigError, parse_config
from sql_warden.engines import EngineUnavailable
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.metrics import Metrics
from sql_warden.pools import PoolSettings, PoolStats
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine

SNOWFLAKE = "snowflake://u:p@account/db/schema?warehouse=wh"


class TestConfig:
    def test_the_defaults(self) -> None:
        pool = parse_config("version: 1\n").warehouse.pool
        assert PoolSettings(**pool.model_dump()) == PoolSettings()
        assert (pool.max_size, pool.max_idle_s, pool.max_lifetime_s, pool.timeout_s) == (
            10,
            300,
            1800,
            5,
        )

    @pytest.mark.parametrize(
        ("setting", "said"),
        [
            ("max_size: 0", "greater than or equal to 1"),
            ("max_lifetime_s: 30", "greater than or equal to 60"),
            ("timeout_s: 0", "greater than 0"),
            ("timeout_s: 120", "less than or equal to 60"),
            ("min_size: 2", "Extra inputs are not permitted"),
        ],
    )
    def test_what_it_refuses(self, setting: str, said: str) -> None:
        with pytest.raises(ConfigError, match=said):
            parse_config(f"version: 1\nwarehouse:\n  pool:\n    {setting}\n")

    def test_not_for_snowflake(self) -> None:
        with pytest.raises(ConfigError, match="pool is for the postgres engine"):
            parse_config(
                f"version: 1\nwarehouse:\n  engine: snowflake\n  dsn: {SNOWFLAKE}\n"
                "  pool:\n    max_size: 3\n"
            )
        # Left out, as everyone without it does, it is no error.
        parse_config(f"version: 1\nwarehouse:\n  engine: snowflake\n  dsn: {SNOWFLAKE}\n")


POLICY = "version: 1\nwarehouse:\n  pool:\n    max_size: 3\n    timeout_s: 2\n"


@pytest.fixture
def policy(tmp_path: Path) -> str:
    path = tmp_path / "warden.yaml"
    path.write_text(POLICY)
    return str(path)


class TestWhoPools:
    def test_a_server(
        self, policy: str, engines: list[FakeEngine], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ran: list[Any] = []
        monkeypatch.setattr(
            cli_module,
            "create_server",
            lambda warden: type("S", (), {"run": lambda self, t: ran.append(t)})(),
        )
        outcome = CliRunner().invoke(cli, ["--config", policy, "serve"])
        assert outcome.exit_code == 0, outcome.output
        (engine,) = engines
        assert engine.pool == PoolSettings(max_size=3, timeout_s=2)

    @pytest.mark.parametrize("command", [["query", "select 1"], ["check", "select 1"], ["tables"]])
    def test_not_a_command_run_by_hand(
        self, policy: str, engines: list[FakeEngine], command: list[str]
    ) -> None:
        # One request, then it exits: there is nothing to keep a connection for.
        outcome = CliRunner().invoke(cli, ["--config", policy, *command])
        assert outcome.exit_code == 0, outcome.output
        assert [engine.pool for engine in engines] == [None]


STATS = PoolStats(open=3, in_use=1, waiting=0, timeouts=2)


class TestMetrics:
    def test_a_watched_pool_is_on_the_page(self) -> None:
        metrics = Metrics()
        metrics.watch_pool("warehouse", "public", lambda: STATS)
        lines = metrics.render().splitlines()
        for line in [
            'sql_warden_pool_connections{pool="warehouse",profile="public"} 3',
            'sql_warden_pool_connections_in_use{pool="warehouse",profile="public"} 1',
            'sql_warden_pool_requests_waiting{pool="warehouse",profile="public"} 0',
            'sql_warden_pool_timeouts_total{pool="warehouse",profile="public"} 2',
            "# TYPE sql_warden_pool_timeouts_total counter",
        ]:
            assert line in lines

    def test_the_last_one_watched_under_a_name_is_reported(self) -> None:
        metrics = Metrics()
        old, new = (lambda: STATS), (lambda: PoolStats(1, 0, 0, 0))
        metrics.watch_pool("warehouse", "public", old)
        metrics.watch_pool("warehouse", "public", new)  # a reload's
        metrics.unwatch_pool("warehouse", "public", old)  # the old one, retired after
        assert 'sql_warden_pool_connections{pool="warehouse",profile="public"} 1' in (
            metrics.render().splitlines()
        )
        metrics.unwatch_pool("warehouse", "public", new)
        assert "sql_warden_pool_connections{" not in metrics.render()

    def test_a_warden_reports_its_engine_s_pool_and_stops_when_closed(self) -> None:
        class Pooled(FakeEngine):
            def pool_stats(self) -> PoolStats:
                return STATS

        metrics = Metrics()
        warden = Warden(Pooled(), audit=MemoryAuditSink(), profile="public", metrics=metrics)
        assert 'profile="public"} 3' in metrics.render()
        warden.close()
        assert "sql_warden_pool_connections{" not in metrics.render()

    def test_an_engine_without_a_pool_reports_none(self) -> None:
        metrics = Metrics()
        Warden(FakeEngine(), audit=MemoryAuditSink(), metrics=metrics)
        assert "sql_warden_pool_connections{" not in metrics.render()


class TestAPooledEngine:
    def test_a_database_it_cant_reach_is_answered_within_the_timeout(self) -> None:
        engine = PostgresEngine(
            "postgresql://warden:hunter2@127.0.0.1:1/warehouse",
            pool=PoolSettings(timeout_s=0.3),
            connect_timeout_s=1,
        )
        try:
            started = time.monotonic()
            with pytest.raises(EngineUnavailable) as raised:
                engine.execute("select 1")
            assert time.monotonic() - started < 2
            assert str(raised.value).startswith(
                "could not connect to the database: connection failed: connection to server at "
                '"127.0.0.1", port 1 failed'
            )
            assert "hunter2" not in str(raised.value)
            stats = engine.pool_stats()
            assert stats is not None
            assert stats.timeouts == 1
        finally:
            engine.close()

    def test_once_closed_it_lends_nothing(self) -> None:
        engine = PostgresEngine("postgresql://127.0.0.1:1/warehouse", pool=PoolSettings())
        engine.close()
        with pytest.raises(EngineUnavailable, match="the server is shutting down"):
            engine.tables()

    def test_one_without_a_pool_has_no_stats_and_nothing_to_close(self) -> None:
        engine = PostgresEngine("postgresql://127.0.0.1:1/warehouse")
        assert engine.pool_stats() is None
        engine.close()
