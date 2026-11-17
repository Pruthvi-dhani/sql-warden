"""The audit log's and the budgets' connection pools without a database: the audit.pool
section, which commands pool, what /metrics says about them, and what a pooled sink says
when it can't get a connection. Against Postgres in
tests/integration/test_audit_pools_on_postgres.py."""

import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from sql_warden import cli as cli_module
from sql_warden.audit import AuditError, AuditEvent, PostgresAuditSink
from sql_warden.cli import cli, watch_audit_pools
from sql_warden.config import ConfigError, parse_config
from sql_warden.metrics import Metrics
from sql_warden.pools import PoolSettings, PoolStats
from sql_warden.sessions import SessionStoreError, Usage
from tests.unit.conftest import AuditSinks, FakeEngine

UNREACHABLE = "postgresql://warden:hunter2@127.0.0.1:1/audit"
EVENT = AuditEvent(profile="public", sql="select 1", decision="allowed", duration_ms=1.0)


class TestConfig:
    def test_the_defaults(self) -> None:
        pool = parse_config("version: 1\n").audit.pool
        assert (pool.max_size, pool.max_idle_s, pool.max_lifetime_s, pool.timeout_s) == (
            5,
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
            parse_config(f"version: 1\naudit:\n  pool:\n    {setting}\n")

    def test_it_is_there_for_a_snowflake_warehouse_too(self) -> None:
        # The audit database is Postgres whatever the warehouse is.
        config = parse_config(
            "version: 1\nwarehouse:\n  engine: snowflake\n"
            "  dsn: snowflake://u:p@account/db/schema?warehouse=wh\n"
            "audit:\n  pool:\n    max_size: 2\n"
        )
        assert config.audit.pool.max_size == 2


POLICY = "version: 1\naudit:\n  pool:\n    max_size: 3\n    timeout_s: 2\n"


@pytest.fixture
def policy(tmp_path: Path) -> str:
    path = tmp_path / "warden.yaml"
    path.write_text(POLICY)
    return str(path)


class TestWhoPools:
    def test_a_server(
        self,
        policy: str,
        engines: list[FakeEngine],
        audit_sinks: AuditSinks,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            cli_module,
            "create_server",
            lambda warden: type("S", (), {"run": lambda self, t: None})(),
        )
        outcome = CliRunner().invoke(cli, ["--config", policy, "serve"])
        assert outcome.exit_code == 0, outcome.output
        # The tables set up on a connection of its own, then the pools opened.
        checked, served = audit_sinks.built
        assert (checked.pool, checked.schema_applied, checked.closed) == (None, True, True)
        assert served.pool == PoolSettings(max_size=3, timeout_s=2)
        assert served.closed  # as the server exits

    @pytest.mark.parametrize("command", [["query", "select 1"], ["check", "select 1"], ["tables"]])
    def test_not_a_command_run_by_hand(
        self,
        policy: str,
        engines: list[FakeEngine],
        audit_sinks: AuditSinks,
        command: list[str],
    ) -> None:
        # One request, then it exits: there is nothing to keep a connection for.
        outcome = CliRunner().invoke(cli, ["--config", policy, *command])
        assert outcome.exit_code == 0, outcome.output
        assert all(sink.pool is None for sink in audit_sinks.built)


STATS = PoolStats(open=2, in_use=1, waiting=0, timeouts=4)


class TestMetrics:
    def test_both_pools_are_on_the_page_without_a_profile(self) -> None:
        class Sink:
            def pool_stats(self) -> dict[str, PoolStats | None]:
                return {"audit": STATS, "budgets": PoolStats(1, 0, 0, 0)}

        metrics = Metrics()
        watch_audit_pools(metrics, Sink())  # type: ignore[arg-type]
        lines = metrics.render().splitlines()
        for line in [
            'sql_warden_pool_connections{pool="audit"} 2',
            'sql_warden_pool_connections_in_use{pool="audit"} 1',
            'sql_warden_pool_timeouts_total{pool="audit"} 4',
            'sql_warden_pool_connections{pool="budgets"} 1',
        ]:
            assert line in lines

    def test_a_sink_without_pools_puts_nothing_there(self) -> None:
        metrics = Metrics()
        watch_audit_pools(metrics, PostgresAuditSink(UNREACHABLE))
        assert "sql_warden_pool_connections{" not in metrics.render()


class TestAPooledSink:
    def test_a_database_it_cant_reach_is_answered_within_the_timeout(self) -> None:
        sink = PostgresAuditSink(UNREACHABLE, connect_timeout_s=1, pool=PoolSettings(timeout_s=0.3))
        try:
            started = time.monotonic()
            with pytest.raises(AuditError) as raised:
                sink.record(EVENT)
            assert time.monotonic() - started < 2
            assert str(raised.value).startswith(
                "could not record the audit event: could not connect to the audit database: "
                'connection failed: connection to server at "127.0.0.1", port 1 failed'
            )
            assert "hunter2" not in str(raised.value)
            stats = sink.pool_stats()["audit"]
            assert stats is not None
            assert stats.timeouts == 1
        finally:
            sink.close()

    def test_a_budget_it_cant_reach_is_budget_unavailable(self) -> None:
        sink = PostgresAuditSink(UNREACHABLE, connect_timeout_s=1, pool=PoolSettings(timeout_s=0.3))
        try:
            store = sink.session_store("public")
            with pytest.raises(SessionStoreError, match="could not charge the session's budget"):
                store.charge("s", Usage(queries=1))
            budgets = sink.pool_stats()["budgets"]
            assert budgets is not None
            assert budgets.timeouts == 1
            audit = sink.pool_stats()["audit"]
            assert audit is not None
            assert audit.timeouts == 0
        finally:
            sink.close()

    def test_its_stores_share_one_pool_which_closing_a_store_leaves_open(self) -> None:
        sink = PostgresAuditSink(UNREACHABLE, pool=PoolSettings(timeout_s=0.3))
        try:
            first, second = sink.session_store("public"), sink.session_store("admin")
            assert first._connections is second._connections is sink._budgets
            first.close()  # a reload retiring a Warden
            with pytest.raises(SessionStoreError, match="could not connect"):
                second.usage("s")  # still trying to connect, not shut
        finally:
            sink.close()

    def test_once_closed_it_lends_nothing(self) -> None:
        sink = PostgresAuditSink(UNREACHABLE, pool=PoolSettings())
        sink.close()
        with pytest.raises(AuditError, match="the server is shutting down"):
            sink.record(EVENT)
        with pytest.raises(SessionStoreError, match="the server is shutting down"):
            sink.session_store("public").usage("s")

    def test_one_without_a_pool_has_no_stats(self) -> None:
        sink = PostgresAuditSink(UNREACHABLE)
        assert sink.pool_stats() == {}
        sink.close()
