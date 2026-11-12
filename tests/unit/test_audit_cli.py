"""sql-warden audit tail | show: rendering and the CLI around the reader."""

import datetime
import json
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from click.testing import CliRunner

from sql_warden import cli as cli_module
from sql_warden.audit import AuditError, AuditEvent, AuditReader
from sql_warden.cli import cli
from sql_warden.config import DEFAULT_AUDIT_DSN
from sql_warden.render import AUDIT_HEADER, audit_json, format_audit_event, format_audit_line

T0 = datetime.datetime(2026, 11, 6, 14, 3, 12, 345000, tzinfo=datetime.UTC)
PASSED = {"check": "parse", "passed": True, "code": None, "reason": None, "duration_ms": 0.42}


@pytest.fixture(autouse=True)
def utc(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Times print in the local zone; make that UTC so the expected output is fixed."""
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def _event(n: int = 1, **fields: Any) -> AuditEvent:
    defaults: dict[str, Any] = {
        "profile": "public",
        "sql": "select id, name from products",
        "decision": "allowed",
        "duration_ms": 12.4,
        "trace": (PASSED,),
        "executed_sql": "SELECT id, name FROM public.products LIMIT 101",
        "rewrites": ("added LIMIT 101 (row cap 100 + 1 to detect truncation)",),
        "client": "claude-code 2.1.3",
        "rows_returned": 3,
        "truncated": False,
        "id": uuid.UUID(int=n),
        "ts": T0 + datetime.timedelta(seconds=n),
    }
    return AuditEvent(**{**defaults, **fields})


REFUSAL = _event(
    2,
    sql="select *\n  from   employee_salaries",
    decision="refused",
    executed_sql=None,
    rewrites=(),
    rows_returned=None,
    truncated=None,
    refused_by="access",
    code="TABLE_NOT_ALLOWED",
    reason="table public.employee_salaries is not available to profile public",
    trace=(
        PASSED,
        {
            "check": "access",
            "passed": False,
            "code": "TABLE_NOT_ALLOWED",
            "reason": "table public.employee_salaries is not available to profile public",
            "duration_ms": 0.2,
        },
    ),
)


class TestTailLines:
    def test_header_and_an_allowed_query(self) -> None:
        assert AUDIT_HEADER.split() == ["ID", "TIME", "KIND", "PROFILE", "CLIENT", "RESULT", "SQL"]
        line = format_audit_line(_event())
        assert line == (
            "00000000  2026-11-06 14:03:13  query  public    claude-code 2.1…  3 rows"
            + " " * 23
            + "select id, name from products"
        )
        # Every column starts where the header says it does.
        for name in ["TIME", "KIND", "PROFILE", "CLIENT", "RESULT", "SQL"]:
            column = AUDIT_HEADER.index(name)
            assert line[column - 2 : column] == "  ", name
            assert line[column] != " ", name

    @pytest.mark.parametrize(
        ("event", "result"),
        [
            (_event(rows_returned=1), "1 row"),
            (_event(rows_returned=100, truncated=True), "100 rows, truncated"),
            (_event(dry_run=True, rows_returned=None, truncated=None), "allowed"),
            (REFUSAL, "refused TABLE_NOT_ALLOWED"),
            (_event(decision="failed", error="division by zero", rows_returned=None), "failed"),
        ],
    )
    def test_the_result(self, event: AuditEvent, result: str) -> None:
        column = AUDIT_HEADER.index("RESULT")
        assert format_audit_line(event)[column:].startswith(result + "  ")

    def test_sql_is_one_line_and_long_sql_is_cut(self) -> None:
        assert format_audit_line(REFUSAL).endswith("select * from employee_salaries")
        long = format_audit_line(_event(sql="select " + ", ".join(["price_cents"] * 20)))
        sql = long[AUDIT_HEADER.index("SQL") :]
        assert len(sql) == 60
        assert sql.endswith("…")

    def test_a_dry_run_is_a_check_and_no_client_is_a_dash(self) -> None:
        line = format_audit_line(_event(dry_run=True, client=None))
        assert line[AUDIT_HEADER.index("KIND") :].startswith("check  ")
        assert line[AUDIT_HEADER.index("CLIENT") :].startswith("-  ")


class TestShow:
    def test_an_allowed_query(self) -> None:
        assert format_audit_event(_event()).splitlines() == [
            "event    00000000-0000-0000-0000-000000000001",
            "time     2026-11-06 14:03:13.345+00:00",
            "profile  public",
            "client   claude-code 2.1.3",
            "kind     query",
            "result   allowed, 3 rows (12 ms)",
            "sql, as sent:",
            "  select id, name from products",
            "sql, as run:",
            "  SELECT id, name FROM public.products LIMIT 101",
            "note: added LIMIT 101 (row cap 100 + 1 to detect truncation)",
            "trace:",
            "  ✓ parse  0.4 ms",
        ]

    def test_a_refusal_keeps_the_sql_as_written(self) -> None:
        lines = format_audit_event(REFUSAL).splitlines()
        assert lines[5] == "result   refused by access: TABLE_NOT_ALLOWED (12 ms)"
        assert lines[6:9] == ["sql, as sent:", "  select *", "    from   employee_salaries"]
        assert lines[-3:] == [
            "trace:",
            "  ✓ parse   0.4 ms",
            "  ✗ access  TABLE_NOT_ALLOWED: table public.employee_salaries is not available to "
            "profile public",
        ]

    def test_a_dry_run_and_a_failure(self) -> None:
        dry = format_audit_event(_event(dry_run=True, rows_returned=None)).splitlines()
        assert dry[4:6] == [
            "kind     check (dry run, nothing was executed)",
            "result   allowed (12 ms)",
        ]
        assert "sql, as it would run:" in dry
        failed = _event(decision="failed", error="division by zero", rows_returned=None)
        assert "result   failed: division by zero (12 ms)" in format_audit_event(failed)

    def test_optional_fields_show_only_when_set(self) -> None:
        text = format_audit_event(
            _event(session_id="s-1", cost_estimate=1234.5, masked_columns=("customers.ssn",))
        )
        assert "session  s-1" in text
        assert "cost     1,234" in text
        assert "masked   customers.ssn" in text
        assert "session" not in format_audit_event(_event())

    def test_json_is_the_row(self) -> None:
        payload = audit_json(REFUSAL)
        assert json.loads(json.dumps(payload)) == payload
        assert payload["id"] == "00000000-0000-0000-0000-000000000002"
        assert payload["ts"] == "2026-11-06T14:03:14.345000+00:00"
        assert payload["trace"][1]["code"] == "TABLE_NOT_ALLOWED"
        assert payload["rewrites"] == []


def test_ids_must_look_like_ids() -> None:
    reader = AuditReader("postgresql://unused/db")
    for bad in ["abc", "zzzz", "28fe 8ea4", ""]:
        with pytest.raises(ValueError, match="is not an audit id"):
            reader.find(bad)


@dataclass
class FakeReader:
    """Stands in for AuditReader in the CLI: polls of since() return the next batch."""

    events: list[AuditEvent] = field(default_factory=list)
    batches: list[list[AuditEvent]] = field(default_factory=list)
    error: AuditError | None = None
    dsn: str = ""
    calls: list[tuple[str, Any]] = field(default_factory=list)
    closed: bool = False

    def recent(self, limit: int, **filters: Any) -> list[AuditEvent]:
        self.calls.append(("recent", (limit, filters)))
        if self.error is not None:
            raise self.error
        return self.events[-limit:]

    def since(self, ts: datetime.datetime, **filters: Any) -> list[AuditEvent]:
        self.calls.append(("since", filters))
        return self.batches.pop(0) if self.batches else []

    def find(self, id_or_prefix: str) -> list[AuditEvent]:
        if self.error is not None:
            raise self.error
        if len(id_or_prefix) < 4:
            raise ValueError(f"'{id_or_prefix}' is not an audit id")
        return [e for e in self.events if str(e.id).startswith(id_or_prefix)]

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def reader(monkeypatch: pytest.MonkeyPatch) -> FakeReader:
    fake = FakeReader()

    def factory(dsn: str, *, connect_timeout_s: int) -> FakeReader:
        fake.dsn = dsn
        return fake

    monkeypatch.setattr(cli_module, "AuditReader", factory)
    return fake


class TestTailCommand:
    def test_prints_the_header_and_events(self, reader: FakeReader) -> None:
        reader.events = [_event(1), REFUSAL]
        outcome = CliRunner().invoke(cli, ["audit", "tail"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines() == [
            AUDIT_HEADER,
            format_audit_line(_event(1)),
            format_audit_line(REFUSAL),
        ]
        assert reader.dsn == DEFAULT_AUDIT_DSN
        assert reader.closed

    def test_options_become_filters(self, reader: FakeReader) -> None:
        CliRunner().invoke(
            cli, ["audit", "tail", "-n", "5", "--profile", "public", "--decision", "refused"]
        )
        filters = {"profile": "public", "decision": "refused", "session_id": None}
        assert reader.calls == [("recent", (5, filters))]

    def test_one_session(self, reader: FakeReader) -> None:
        CliRunner().invoke(cli, ["audit", "tail", "--session", "nightly-report"])
        filters = {"profile": None, "decision": None, "session_id": "nightly-report"}
        assert reader.calls == [("recent", (20, filters))]

    def test_an_empty_log(self, reader: FakeReader) -> None:
        assert CliRunner().invoke(cli, ["audit", "tail"]).output == "(no audit events)\n"
        assert CliRunner().invoke(cli, ["audit", "tail", "--json"]).output == ""

    def test_json_lines(self, reader: FakeReader) -> None:
        reader.events = [_event(1), REFUSAL]
        lines = CliRunner().invoke(cli, ["audit", "tail", "--json"]).output.splitlines()
        assert [json.loads(line)["id"] for line in lines] == [str(_event(1).id), str(REFUSAL.id)]

    def test_follow_prints_each_new_event_once(
        self, reader: FakeReader, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = datetime.datetime.now(datetime.UTC)
        old = _event(1, ts=now - datetime.timedelta(seconds=3))
        new = _event(7, ts=now + datetime.timedelta(seconds=1))
        late = _event(8, ts=now)  # finished earlier, written later
        reader.events = [old]
        reader.batches = [
            [old],  # what was already there when following began: not printed again
            [old, new],
            [old, late, new],
            [],
        ]
        polls = []

        def sleep(seconds: float) -> None:
            polls.append(seconds)
            if len(polls) == 4:
                raise KeyboardInterrupt

        monkeypatch.setattr(cli_module, "_sleep", sleep)
        outcome = CliRunner().invoke(cli, ["audit", "tail", "-f", "--profile", "admin"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines() == [
            AUDIT_HEADER,
            format_audit_line(old),
            format_audit_line(new),
            format_audit_line(late),
        ]
        assert reader.closed
        assert all(f["profile"] == "admin" for kind, f in reader.calls if kind == "since")

    def test_an_unreachable_database(self, reader: FakeReader) -> None:
        reader.error = AuditError("could not read the audit log: connection refused")
        outcome = CliRunner().invoke(
            cli, ["audit", "tail", "--audit-dsn", "postgresql://u:hunter2@audit.internal/a"]
        )
        assert outcome.exit_code == 1
        assert outcome.output == (
            "Error: audit database at audit.internal/a as u: could not read the audit log: "
            "connection refused\n"
        )
        assert reader.closed


class TestShowCommand:
    def test_shows_one_event_by_prefix(self, reader: FakeReader) -> None:
        reader.events = [REFUSAL]
        outcome = CliRunner().invoke(cli, ["audit", "show", "00000000-0000-0000-0000-00000000000"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output == format_audit_event(REFUSAL) + "\n"

    def test_json(self, reader: FakeReader) -> None:
        reader.events = [REFUSAL]
        output = CliRunner().invoke(cli, ["audit", "show", str(REFUSAL.id), "--json"]).output
        assert json.loads(output) == audit_json(REFUSAL)

    def test_unknown_ambiguous_and_malformed_ids(self, reader: FakeReader) -> None:
        reader.events = [_event(1), REFUSAL]
        runner = CliRunner()
        missing = runner.invoke(cli, ["audit", "show", "ffffffff"])
        assert (missing.exit_code, missing.output) == (1, "Error: no audit event ffffffff\n")
        ambiguous = runner.invoke(cli, ["audit", "show", "0000"])
        assert ambiguous.exit_code == 1
        assert "more than one audit event id starts with 0000; give more of it" in ambiguous.output
        malformed = runner.invoke(cli, ["audit", "show", "ab"])
        assert malformed.exit_code == 1
        assert "'ab' is not an audit id" in malformed.output
