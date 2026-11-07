"""Every request leaves exactly one audit event, and nothing is returned without one."""

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from mcp import Client
from mcp_types import Implementation

from sql_warden.audit import AuditError, AuditEvent, MemoryAuditSink
from sql_warden.cli import EXIT_ERROR, NOT_RECORDED, cli
from sql_warden.config import DEFAULT_AUDIT_DSN, ConfigError, parse_config
from sql_warden.engines import QueryFailed, QueryTimeout, Result
from sql_warden.models import RefusalCode
from sql_warden.server import create_server, describe
from sql_warden.warden import Warden
from tests.unit.conftest import AuditSinks, FakeEngine

DOWN = AuditError("the audit database is unavailable: connection refused")
GONE = AuditError("could not record the audit event: gone")


class RecordFails(MemoryAuditSink):
    """Reachable when asked, then fails to write: the audit database went away mid-query."""

    def __init__(self, error: Exception = GONE) -> None:
        super().__init__()
        self.error = error

    def record(self, event: AuditEvent) -> None:
        raise self.error


def _warden(engine: FakeEngine | None = None, audit: Any = None) -> Warden:
    return Warden(engine or FakeEngine(), audit=MemoryAuditSink() if audit is None else audit)


def _only_event(warden: Warden) -> AuditEvent:
    assert isinstance(warden.audit, MemoryAuditSink)
    (event,) = warden.audit.events
    return event


class TestOneEventPerRequest:
    def test_an_allowed_run(self) -> None:
        warden = _warden()
        outcome = warden.run("select 1 as id", client="tester 1.0")
        event = _only_event(warden)
        assert outcome.decision.audit_id == event.id
        assert (event.decision, event.dry_run, event.profile, event.client) == (
            "allowed",
            False,
            "all",
            "tester 1.0",
        )
        assert event.sql == "select 1 as id"
        assert event.executed_sql == "SELECT 1 AS id LIMIT 101"
        assert event.rewrites == ("added LIMIT 101 (row cap 100 + 1 to detect truncation)",)
        assert (event.rows_returned, event.truncated) == (1, False)
        assert (event.refused_by, event.code, event.reason, event.error) == (None,) * 4
        assert [step["check"] for step in event.trace] == ["parse", "shape", "cost"]
        assert event.duration_ms > 0

    def test_a_dry_run(self) -> None:
        engine = FakeEngine()
        warden = _warden(engine)
        decision = warden.check("select 1 as id")
        event = _only_event(warden)
        assert decision.audit_id == event.id
        assert (event.decision, event.dry_run) == ("allowed", True)
        assert event.executed_sql == "SELECT 1 AS id LIMIT 101"  # what would run
        assert (event.rows_returned, event.truncated) == (None, None)
        assert engine.executed == []

    @pytest.mark.parametrize("dry_run", [False, True])
    def test_a_refusal(self, dry_run: bool) -> None:
        engine = FakeEngine()
        warden = _warden(engine)
        sql = "delete from orders"
        decision = warden.check(sql) if dry_run else warden.run(sql).decision
        event = _only_event(warden)
        assert decision.audit_id == event.id
        assert (event.decision, event.dry_run) == ("refused", dry_run)
        assert (event.refused_by, event.code) == ("shape", "NOT_A_SELECT")
        assert event.reason == "only SELECT queries are allowed, not DELETE"
        assert event.executed_sql is None
        assert event.trace[-1] == {
            "check": "shape",
            "passed": False,
            "code": "NOT_A_SELECT",
            "reason": "only SELECT queries are allowed, not DELETE",
            "duration_ms": event.trace[-1]["duration_ms"],
        }
        assert engine.executed == []

    def test_a_database_error(self) -> None:
        warden = _warden(FakeEngine(error=QueryFailed("division by zero", "22012")))
        outcome = warden.run("select 1 / 0")
        event = _only_event(warden)
        assert outcome.decision.audit_id == event.id
        assert (event.decision, event.error) == ("failed", "division by zero")
        assert event.executed_sql == "SELECT 1 / 0 LIMIT 101"
        assert (event.rows_returned, event.code) == (None, None)

    def test_a_timeout(self) -> None:
        timeout = QueryTimeout("query cancelled: it ran past the 5000 ms statement timeout")
        warden = _warden(FakeEngine(error=timeout))
        warden.run("select 1")
        event = _only_event(warden)
        assert (event.decision, event.error) == ("failed", str(timeout))

    def test_truncated_results(self) -> None:
        rows = Result(columns=("id",), rows=((1,), (2,)), truncated=True, duration_ms=1.0)
        warden = _warden(FakeEngine(result=rows))
        warden.run("select id from products")
        assert (_only_event(warden).rows_returned, _only_event(warden).truncated) == (2, True)

    def test_a_crash_in_the_engine_is_recorded_and_raised(self) -> None:
        class Broken(FakeEngine):
            def execute(self, sql: str) -> Result:
                raise RuntimeError("bug")

        warden = _warden(Broken())
        with pytest.raises(RuntimeError, match="bug"):
            warden.run("select 1")
        event = _only_event(warden)
        assert (event.decision, event.error) == ("failed", "unexpected RuntimeError")

    def test_the_profile_is_recorded(self) -> None:
        warden = Warden(FakeEngine(), audit=MemoryAuditSink(), profile="public")
        warden.run("select 1")
        assert _only_event(warden).profile == "public"

    def test_the_recorded_trace_is_the_returned_one(self) -> None:
        warden = _warden()
        outcome = warden.run("select 1")
        returned = describe(outcome.decision, outcome).model_dump()["trace"]
        assert list(_only_event(warden).trace) == returned

    def test_each_request_is_its_own_event(self) -> None:
        warden = _warden()
        ids = {warden.run("select 1").decision.audit_id for _ in range(3)}
        ids.add(warden.check("select 1").audit_id)
        assert len(ids) == 4
        assert isinstance(warden.audit, MemoryAuditSink)
        assert len(warden.audit.events) == 4


class TestFailClosed:
    def test_audit_down_means_the_query_never_runs(self) -> None:
        engine = FakeEngine()
        sink = MemoryAuditSink()
        sink.fail_with = DOWN
        outcome = _warden(engine, sink).run("select 1")
        assert engine.executed == []
        assert outcome.result is None
        refused = outcome.decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert (refused.check, refused.refusal.code) == ("audit", RefusalCode.AUDIT_UNAVAILABLE)
        assert refused.refusal.reason == f"{DOWN}; the query was not run"
        assert outcome.decision.sql is None
        assert outcome.decision.audit_id is None

    def test_a_failed_write_after_the_query_withholds_its_rows(self) -> None:
        engine = FakeEngine()
        outcome = _warden(engine, RecordFails()).run("select 1")
        assert engine.executed == ["SELECT 1 LIMIT 101"]  # it ran ...
        assert outcome.result is None  # ... but nothing comes back
        refused = outcome.decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert refused.refusal.code == RefusalCode.AUDIT_UNAVAILABLE
        assert refused.refusal.reason == (
            "could not record the audit event: gone; the query ran, but its results are withheld"
        )
        checks = [entry.check for entry in outcome.decision.trace]
        assert checks == ["parse", "shape", "cost", "audit"]

    def test_a_failed_database_error_is_withheld_too(self) -> None:
        engine = FakeEngine(error=QueryFailed("relation does not exist"))
        outcome = _warden(engine, RecordFails()).run("select 1")
        assert outcome.error is None
        refused = outcome.decision.refused_by
        assert refused is not None
        assert refused.check == "audit"

    @pytest.mark.parametrize("dry_run", [False, True])
    def test_a_refusal_that_cant_be_recorded_says_so(self, dry_run: bool) -> None:
        warden = _warden(audit=RecordFails())
        sql = "delete from orders"
        decision = warden.check(sql) if dry_run else warden.run(sql).decision
        refused = decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert refused.refusal.code == RefusalCode.AUDIT_UNAVAILABLE
        assert refused.refusal.reason.endswith("nothing is returned without an audit record")
        # The trace still shows what the checks decided.
        assert [(entry.check, entry.passed) for entry in decision.trace] == [
            ("parse", True),
            ("shape", False),
            ("audit", False),
        ]

    def test_a_dry_run_that_cant_be_recorded_shows_no_sql(self) -> None:
        decision = _warden(audit=RecordFails()).check("select 1")
        assert not decision.allowed
        assert (decision.sql, decision.rewrites) == (None, ())

    @pytest.mark.parametrize("where", ["ping", "record"])
    def test_a_bug_in_the_sink_fails_closed_without_its_message(self, where: str) -> None:
        class Buggy(MemoryAuditSink):
            def ping(self) -> None:
                if where == "ping":
                    raise ValueError("postgresql://user:secret@host/db")

            def record(self, event: AuditEvent) -> None:
                raise ValueError("postgresql://user:secret@host/db")

        engine = FakeEngine()
        outcome = _warden(engine, Buggy()).run("select 1")
        refused = outcome.decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert refused.refusal.code == RefusalCode.AUDIT_UNAVAILABLE
        assert "unexpected ValueError" in refused.refusal.reason
        assert "secret" not in refused.refusal.reason
        assert engine.executed == ([] if where == "ping" else ["SELECT 1 LIMIT 101"])

    def test_commands_that_record_nothing_cant_run_queries(self) -> None:
        outcome = Warden(FakeEngine(), audit=NOT_RECORDED).run("select 1")
        assert outcome.result is None
        refused = outcome.decision.refused_by
        assert refused is not None
        assert refused.check == "audit"


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
class TestMcp:
    async def test_the_client_name_is_recorded(self, anyio_backend: str) -> None:
        warden = _warden()
        info = Implementation(name="claude-code", version="2.1.3")
        async with Client(create_server(warden), client_info=info) as client:
            result = await client.call_tool("run_query", {"sql": "select 1"})
            await client.call_tool("check_query", {"sql": "select 1"})
        assert result.structured_content is not None
        assert isinstance(warden.audit, MemoryAuditSink)
        first, second = warden.audit.events
        assert result.structured_content["audit_id"] == str(first.id)
        assert (first.client, first.dry_run, second.dry_run) == ("claude-code 2.1.3", False, True)

    async def test_a_dry_run_that_cant_be_recorded_is_an_error(self, anyio_backend: str) -> None:
        async with Client(create_server(_warden(audit=RecordFails()))) as client:
            result = await client.call_tool("check_query", {"sql": "select 1"})
        assert result.is_error
        assert result.structured_content is not None
        assert result.structured_content["code"] == "AUDIT_UNAVAILABLE"
        assert "audit_id" not in result.structured_content


class TestCli:
    def test_query_and_check_are_recorded_as_cli(
        self, engines: list[FakeEngine], audit_sinks: AuditSinks
    ) -> None:
        CliRunner().invoke(cli, ["query", "select 1"])
        CliRunner().invoke(cli, ["check", "select 1"])
        assert [(e.client, e.dry_run) for e in audit_sinks.events] == [
            ("cli", False),
            ("cli", True),
        ]
        assert all(sink.schema_applied for sink in audit_sinks.built)

    def test_the_demo_audit_database_is_the_default(
        self, engines: list[FakeEngine], audit_sinks: AuditSinks
    ) -> None:
        CliRunner().invoke(cli, ["check", "select 1"])
        assert audit_sinks.built[0].dsn == DEFAULT_AUDIT_DSN

    def test_the_audit_dsn_option_and_env(
        self, engines: list[FakeEngine], audit_sinks: AuditSinks, isolated_cli: Path
    ) -> None:
        (isolated_cli / "warden.yaml").write_text(
            "version: 1\naudit:\n  dsn: postgresql://from-file/audit\n  connect_timeout_s: 2\n"
        )
        runner = CliRunner()
        runner.invoke(cli, ["check", "select 1"])
        runner.invoke(cli, ["check", "select 1"], env={"SQL_WARDEN_AUDIT_DSN": "postgresql://e/a"})
        runner.invoke(cli, ["check", "select 1", "--audit-dsn", "postgresql://flag/audit"])
        assert [(sink.dsn, sink.connect_timeout_s) for sink in audit_sinks.built] == [
            ("postgresql://from-file/audit", 2),
            ("postgresql://e/a", 2),
            ("postgresql://flag/audit", 2),
        ]

    @pytest.mark.parametrize("command", [["query", "select 1"], ["check", "select 1"], ["serve"]])
    def test_nothing_starts_without_the_audit_database(
        self, engines: list[FakeEngine], audit_sinks: AuditSinks, command: list[str]
    ) -> None:
        audit_sinks.fail_with = AuditError("could not set up the audit table: connection refused")
        outcome = CliRunner().invoke(
            cli, [*command, "--audit-dsn", "postgresql://warden_audit:hunter2@audit.internal/a"]
        )
        assert outcome.exit_code == EXIT_ERROR
        assert outcome.output.splitlines() == [
            "Error: audit database at audit.internal/a as warden_audit: could not set up the "
            "audit table: connection refused",
            "sql-warden records every request and won't run without its audit database.",
        ]
        assert "hunter2" not in outcome.output
        assert engines == []

    def test_listing_tables_needs_no_audit_database(
        self, engines: list[FakeEngine], audit_sinks: AuditSinks
    ) -> None:
        audit_sinks.fail_with = DOWN
        outcome = CliRunner().invoke(cli, ["tables"])
        assert outcome.exit_code == 0, outcome.output
        assert audit_sinks.built == []

    def test_json_carries_the_audit_id(
        self, engines: list[FakeEngine], audit_sinks: AuditSinks
    ) -> None:
        payload = json.loads(CliRunner().invoke(cli, ["check", "select 1", "--json"]).output)
        assert payload["audit_id"] == str(audit_sinks.events[0].id)


class TestConfig:
    def test_defaults_to_the_demo_stack(self) -> None:
        audit = parse_config("version: 1").audit
        assert (audit.dsn, audit.connect_timeout_s) == (DEFAULT_AUDIT_DSN, 5)

    def test_there_is_no_way_to_turn_it_off(self) -> None:
        with pytest.raises(ConfigError, match=r"audit\.enabled: Extra inputs are not permitted"):
            parse_config("version: 1\naudit:\n  enabled: false\n")
