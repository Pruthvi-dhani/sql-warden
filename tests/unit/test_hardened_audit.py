"""What a server and `config validate --live` make of an audit role that could change what it
records, and the arguments of `audit prune` and `audit export`. Against Postgres, with the
deploy roles, in tests/integration/test_hardened_audit_on_postgres.py."""

import datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sql_warden import cli as cli_module
from sql_warden.audit import AuditError
from sql_warden.audit.retention import MIN_AGE, parse_age, prune
from sql_warden.cli import ONLY_APPENDS, cli
from tests.unit.conftest import AuditSinks, FakeAuditSink, FakeEngine

SUPERUSER = ("is a superuser",)


class TestAges:
    @pytest.mark.parametrize(
        ("text", "age"),
        [
            ("90d", datetime.timedelta(days=90)),
            ("36h", datetime.timedelta(hours=36)),
            (" 1d ", MIN_AGE),
            ("24h", MIN_AGE),
        ],
    )
    def test_days_or_hours(self, text: str, age: datetime.timedelta) -> None:
        assert parse_age(text) == age

    @pytest.mark.parametrize("text", ["90", "3w", "-5d", "d", "1.5d", ""])
    def test_anything_else_is_refused(self, text: str) -> None:
        with pytest.raises(ValueError, match="give days or hours"):
            parse_age(text)

    @pytest.mark.parametrize("text", ["0d", "23h"])
    def test_never_less_than_a_day(self, text: str) -> None:
        with pytest.raises(ValueError, match="younger than a day"):
            parse_age(text)

    def test_nor_by_calling_prune_directly(self) -> None:
        with pytest.raises(ValueError, match="younger than a day"):
            prune("postgresql://nowhere/audit", datetime.timedelta(hours=1))


class TestArguments:
    def test_prune_needs_an_age_of_a_day_or_more(self) -> None:
        outcome = CliRunner().invoke(cli, ["audit", "prune", "--older-than", "12h"])
        assert outcome.exit_code == 1
        assert "records younger than a day are never pruned" in outcome.output

    def test_export_needs_a_window(self) -> None:
        backwards = ["audit", "export", "--since", "2026-11-02", "--until", "2026-11-01"]
        outcome = CliRunner().invoke(cli, backwards)
        assert outcome.exit_code == 1
        assert "--until must be after --since" in outcome.output
        garbled = CliRunner().invoke(cli, ["audit", "export", "--since", "last tuesday"])
        assert garbled.exit_code == 1
        assert "'last tuesday' is not a date or time" in garbled.output

    def test_a_time_without_a_zone_is_utc(self) -> None:
        ts = cli_module._Timestamp().convert("2026-11-01 09:30", None, None)
        assert ts == datetime.datetime(2026, 11, 1, 9, 30, tzinfo=datetime.UTC)
        offset = cli_module._Timestamp().convert("2026-11-01T09:30+05:30", None, None)
        assert offset.utcoffset() == datetime.timedelta(hours=5, minutes=30)


@pytest.fixture
def engines(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "PostgresEngine", lambda dsn, **_: FakeEngine(dsn))


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch, engines: None) -> list[str]:
    served: list[str] = []
    monkeypatch.setattr(
        cli_module,
        "create_server",
        lambda warden: type("S", (), {"run": lambda self, t: served.append(warden.profile)})(),
    )
    return served


def _policy(tmp_path: Path, *, append_only: bool) -> str:
    path = tmp_path / "warden.yaml"
    path.write_text(
        "version: 1\naudit:\n"
        "  dsn: postgresql://warden_audit:hunter2@audit.internal/audit\n"
        f"  append_only: {str(append_only).lower()}\n"
    )
    return str(path)


WARNING = [
    "warning: the audit role (audit.internal/audit as warden_audit) can change or remove what "
    "is recorded:",
    "  it is a superuser",
    ONLY_APPENDS,
]


class TestServe:
    def test_an_audit_role_that_only_adds_is_served_quietly(
        self, served: list[str], tmp_path: Path
    ) -> None:
        outcome = CliRunner().invoke(
            cli, ["--config", _policy(tmp_path, append_only=True), "serve"]
        )
        assert (outcome.exit_code, outcome.stderr, served) == (0, "", ["all"])

    def test_one_that_could_tamper_is_warned_about(
        self, served: list[str], audit_sinks: AuditSinks, tmp_path: Path
    ) -> None:
        audit_sinks.can_tamper = SUPERUSER
        outcome = CliRunner().invoke(
            cli, ["--config", _policy(tmp_path, append_only=False), "serve"]
        )
        assert outcome.exit_code == 0
        assert outcome.stderr.splitlines() == WARNING
        assert "hunter2" not in outcome.output
        assert served == ["all"]

    @pytest.mark.parametrize("transport", ["stdio", "http"])
    def test_and_with_append_only_refused(
        self,
        served: list[str],
        audit_sinks: AuditSinks,
        tmp_path: Path,
        transport: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        listened: list[Any] = []
        monkeypatch.setattr(cli_module, "_listen", lambda *args: listened.append(args))
        audit_sinks.can_tamper = SUPERUSER
        outcome = CliRunner().invoke(
            cli,
            [
                "--config",
                _policy(tmp_path, append_only=True),
                "serve",
                "--transport",
                transport,
            ],
        )
        assert outcome.exit_code == 1
        assert outcome.output.splitlines() == [
            "Error: the audit role (audit.internal/audit as warden_audit) can change or "
            "remove what is recorded:",
            "  it is a superuser",
            ONLY_APPENDS,
            "audit.append_only is set.",
        ]
        assert (served, listened) == ([], [])

    def test_an_audit_database_that_cant_say_isnt_served(
        self,
        served: list[str],
        audit_sinks: AuditSinks,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def unanswered(self: Any) -> None:
            raise AuditError("could not check what the audit role can do: timeout")

        monkeypatch.setattr(FakeAuditSink, "tampering", unanswered)
        outcome = CliRunner().invoke(
            cli, ["--config", _policy(tmp_path, append_only=False), "serve"]
        )
        assert outcome.exit_code == 1
        assert outcome.output.startswith("Error: audit database at audit.internal/audit")
        assert served == []


class TestValidateLive:
    def _validate(self, tmp_path: Path, *, append_only: bool = False) -> Any:
        return CliRunner().invoke(
            cli, ["config", "validate", _policy(tmp_path, append_only=append_only), "--live"]
        )

    def test_a_role_that_only_adds(self, engines: None, tmp_path: Path) -> None:
        outcome = self._validate(tmp_path, append_only=True)
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines()[-1] == "  audit:     its role can only add records"

    def test_one_that_could_tamper_is_flagged(
        self, engines: None, audit_sinks: AuditSinks, tmp_path: Path
    ) -> None:
        audit_sinks.can_tamper = ("owns audit_events", "can DELETE on audit_events")
        outcome = self._validate(tmp_path)
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines()[-3:] == [
            "  audit:     ! its role can change or remove records:",
            "               it owns audit_events",
            "               it can DELETE on audit_events",
        ]

    def test_and_fails_it_with_append_only(
        self, engines: None, audit_sinks: AuditSinks, tmp_path: Path
    ) -> None:
        audit_sinks.can_tamper = SUPERUSER
        outcome = self._validate(tmp_path, append_only=True)
        assert outcome.exit_code == 1
        assert outcome.output.splitlines()[-3:] == [
            "  audit:     ✗ its role can change or remove records:",
            "               it is a superuser",
            f"Error: a server would not start, since audit.append_only is set. {ONLY_APPENDS}",
        ]

    def test_no_tables_yet(self, engines: None, audit_sinks: AuditSinks, tmp_path: Path) -> None:
        audit_sinks.can_tamper = None
        outcome = self._validate(tmp_path)
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines()[-1] == (
            "  audit:     no audit tables yet: `sql-warden audit init` makes them"
        )

    def test_an_audit_database_that_cant_be_reached(
        self, engines: None, audit_sinks: AuditSinks, tmp_path: Path
    ) -> None:
        audit_sinks.fail_with = AuditError("could not check what the audit role can do: refused")
        outcome = self._validate(tmp_path)
        assert outcome.exit_code == 1
        assert outcome.output.splitlines()[-2:] == [
            "  audit:     ✗ could not check its role: could not check what the audit role can "
            "do: refused",
            "Error: a server would not start: it records every request, and can't reach the "
            "audit database",
        ]
