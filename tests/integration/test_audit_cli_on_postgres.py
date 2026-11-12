"""sql-warden audit tail | show against seeded rows in a real audit database."""

import datetime
import json
import uuid
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest
from click.testing import CliRunner

from sql_warden import cli as cli_module
from sql_warden.audit import AuditEvent, PostgresAuditSink
from sql_warden.cli import cli
from sql_warden.render import AUDIT_HEADER, audit_json, format_audit_event, format_audit_line
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration

T0 = datetime.datetime(2026, 11, 6, 9, 0, tzinfo=datetime.UTC)


def _event(n: int, **fields: Any) -> AuditEvent:
    defaults: dict[str, Any] = {
        "profile": "public",
        "sql": f"select {n}",
        "decision": "allowed",
        "duration_ms": 1.5,
        "client": "cli",
        "rows_returned": 1,
        "truncated": False,
        "trace": (
            {"check": "parse", "passed": True, "code": None, "reason": None, "duration_ms": 0.1},
        ),
        "ts": T0 + datetime.timedelta(minutes=n),
    }
    return AuditEvent(**{**defaults, **fields})


SEEDED = [
    _event(1, session_id="nightly-report"),
    _event(2, profile="admin", sql="select count(*) from employee_salaries"),
    _event(
        3,
        decision="refused",
        sql="select * from employee_salaries",
        refused_by="access",
        code="TABLE_NOT_ALLOWED",
        reason="table public.employee_salaries is not available to profile public",
        rows_returned=None,
        truncated=None,
        id=uuid.UUID("abcd0000-0000-4000-8000-000000000001"),
    ),
    _event(
        4,
        decision="failed",
        error="division by zero",
        rows_returned=None,
        truncated=None,
        session_id="nightly-report",
    ),
    _event(
        5,
        dry_run=True,
        rows_returned=None,
        truncated=None,
        id=uuid.UUID("abcd0000-0000-4000-8000-000000000002"),
    ),
]


@pytest.fixture
def sink(audit_dsn: str) -> Iterator[PostgresAuditSink]:
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS audit_events")
    sink = PostgresAuditSink(audit_dsn)
    sink.ensure_schema()
    for event in SEEDED:
        sink.record(event)
    yield sink
    sink.close()


def _run(*args: str) -> tuple[int, str]:
    outcome = CliRunner().invoke(cli, ["audit", *args])
    return outcome.exit_code, outcome.output


def test_tail_shows_the_latest_oldest_first(sink: PostgresAuditSink) -> None:
    code, output = _run("tail", "-n", "3")
    assert code == 0, output
    assert output.splitlines() == [AUDIT_HEADER, *(format_audit_line(e) for e in SEEDED[2:])]


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        (["--profile", "admin"], [SEEDED[1]]),
        (["--decision", "refused"], [SEEDED[2]]),
        (["--profile", "public", "--decision", "allowed", "-n", "1"], [SEEDED[4]]),
        (["--profile", "nobody"], []),
        (["--session", "nightly-report"], [SEEDED[0], SEEDED[3]]),
        (["--session", "nightly-report", "--decision", "failed"], [SEEDED[3]]),
        (["--session", "nightly"], []),  # the whole name, not the start of one
    ],
)
def test_tail_filters(
    sink: PostgresAuditSink, options: list[str], expected: list[AuditEvent]
) -> None:
    code, output = _run("tail", "--json", *options)
    assert code == 0, output
    assert [json.loads(line) for line in output.splitlines()] == [audit_json(e) for e in expected]


def test_tail_json_round_trips_every_field(sink: PostgresAuditSink) -> None:
    code, output = _run("tail", "--json")
    assert code == 0, output
    assert [json.loads(line) for line in output.splitlines()] == [audit_json(e) for e in SEEDED]


def test_show_by_id_and_by_prefix(sink: PostgresAuditSink) -> None:
    refusal = SEEDED[2]
    assert _run("show", str(refusal.id)) == (0, format_audit_event(refusal) + "\n")
    assert _run("show", str(SEEDED[0].id)[:8].upper())[1] == format_audit_event(SEEDED[0]) + "\n"
    assert json.loads(_run("show", str(refusal.id), "--json")[1]) == audit_json(refusal)


def test_show_refuses_an_ambiguous_or_unknown_id(sink: PostgresAuditSink) -> None:
    code, output = _run("show", "abcd0000")
    assert code == 1
    assert "more than one audit event id starts with abcd0000" in output
    assert _run("show", "abcd0000-0000-4000-8000-000000000002")[0] == 0
    assert _run("show", "ffffffff") == (1, "Error: no audit event ffffffff\n")
    assert _run("show", str(uuid.uuid4()))[0] == 1


def test_follow_prints_what_is_recorded_while_it_runs(
    sink: PostgresAuditSink, monkeypatch: pytest.MonkeyPatch
) -> None:
    recorded = _event(9, ts=datetime.datetime.now(datetime.UTC), sql="select 'new'")
    polls = []

    def sleep(seconds: float) -> None:
        polls.append(seconds)
        if len(polls) == 1:
            sink.record(recorded)  # an agent's query lands while tail waits
        else:
            raise KeyboardInterrupt

    monkeypatch.setattr(cli_module, "_sleep", sleep)
    code, output = _run("tail", "-n", "1", "-f")
    assert code == 0, output
    assert output.splitlines() == [
        AUDIT_HEADER,
        format_audit_line(SEEDED[-1]),
        format_audit_line(recorded),
    ]


def test_a_request_can_be_looked_up_by_its_audit_id(
    warehouse: Warehouse, sink: PostgresAuditSink
) -> None:
    outcome = CliRunner().invoke(
        cli,
        ["query", "select name from products where id = 7", "--json"],
        env={"SQL_WARDEN_DSN": warehouse.reader_dsn},
    )
    payload = json.loads(outcome.output)
    audit_id, session_id = payload["audit_id"], payload["session_id"]
    code, output = _run("show", audit_id[:8])
    assert code == 0, output
    lines = output.splitlines()
    assert lines[0] == f"event    {audit_id}"
    assert lines[4] == f"session  {session_id}"
    assert lines[6].startswith("result   allowed, 1 row (")
    assert "  SELECT name FROM products WHERE id = 7 LIMIT 101" in lines
    # And everything its session asked: here, just that.
    code, output = _run("tail", "--session", session_id, "--json")
    assert [json.loads(line)["id"] for line in output.splitlines()] == [audit_id]


def test_before_anything_is_recorded(audit_dsn: str) -> None:
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS audit_events")
    assert _run("tail") == (0, "(no audit events)\n")
    assert _run("show", "abcd") == (1, "Error: no audit event abcd\n")


def test_an_unreachable_audit_database() -> None:
    code, output = _run("tail", "--audit-dsn", "postgresql://u:hunter2@127.0.0.1:1/audit")
    assert code == 1
    assert output.startswith("Error: audit database at 127.0.0.1:1/audit as u: could not read")
    assert "hunter2" not in output
