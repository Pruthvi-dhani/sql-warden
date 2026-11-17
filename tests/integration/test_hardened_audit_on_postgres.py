"""The hardened audit database: deploy/audit_roles.sql's roles in a database of their own,
the tables made by their owner, and what each role can and can't do to the records."""

import datetime
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from click.testing import CliRunner
from psycopg.conninfo import make_conninfo

from sql_warden.audit import AuditError, AuditEvent, PostgresAuditSink
from sql_warden.cli import cli
from sql_warden.config import BudgetConfig
from sql_warden.pools import PoolSettings
from sql_warden.sessions import Usage

pytestmark = pytest.mark.integration

ROOT = Path(__file__).parents[2]
ROLES_SQL = (ROOT / "deploy" / "audit_roles.sql").read_text()
DATABASE = "hardened_audit"
GROUPS = ("sql_warden_owner", "sql_warden_writer", "sql_warden_pruner", "sql_warden_reader")
LOGINS = {
    "hw_admin": "sql_warden_owner",
    "hw_warden": "sql_warden_writer",
    "hw_retention": "sql_warden_pruner",
    "hw_analyst": "sql_warden_reader",
}
NOW = datetime.datetime.now(datetime.UTC)


class Audit:
    """The hardened database, and a connection string for each of its logins."""

    def __init__(self, admin: str) -> None:
        self.admin = admin  # the container's superuser, in the hardened database

    def dsn(self, login: str) -> str:
        return make_conninfo(self.admin, user=login, password=login)

    def sql(self, statement: str, params: Any = None) -> list[Any]:
        with psycopg.connect(self.admin, autocommit=True) as conn:
            cursor = conn.execute(statement, params)
            return cursor.fetchall() if cursor.description else []

    def cli(self, login: str, *args: str) -> Any:
        return CliRunner().invoke(cli, [*args, "--audit-dsn", self.dsn(login)])


def _drop(server: str) -> None:
    with psycopg.connect(server, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {DATABASE} WITH (FORCE)")
        roles = [*LOGINS, *GROUPS]
        existing = {r for (r,) in conn.execute("SELECT rolname FROM pg_roles").fetchall()}
        present = [role for role in roles if role in existing]
        if present:
            # Grants other tests' schemas made to the groups, in the main audit database.
            conn.execute(f"DROP OWNED BY {', '.join(present)}")
            conn.execute(f"DROP ROLE {', '.join(present)}")


@pytest.fixture(scope="module")
def audit(audit_dsn: str) -> Iterator[Audit]:
    _drop(audit_dsn)
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute(f"CREATE DATABASE {DATABASE}")
    hardened = Audit(make_conninfo(audit_dsn, dbname=DATABASE))
    hardened.sql(ROLES_SQL)
    hardened.sql(ROLES_SQL)  # safe to run again
    for login, group in LOGINS.items():
        hardened.sql(f"CREATE ROLE {login} LOGIN PASSWORD '{login}' IN ROLE {group}")
    made = hardened.cli("hw_admin", "audit", "init", "--owner", "sql_warden_owner")
    assert made.exit_code == 0, made.output
    try:
        yield hardened
    finally:
        _drop(audit_dsn)


@pytest.fixture
def empty(audit: Audit) -> Audit:
    audit.sql("TRUNCATE audit_events, session_usage, caller_charges, audit_prunes")
    return audit


def _event(**fields: Any) -> AuditEvent:
    return AuditEvent(
        **{
            "profile": "support",
            "sql": "select 1",
            "decision": "allowed",
            "duration_ms": 1.0,
            **fields,
        }
    )


class TestTheTables:
    def test_are_the_owner_s(self, audit: Audit) -> None:
        owners = audit.sql(
            "SELECT c.relname, pg_get_userbyid(c.relowner) FROM pg_class c "
            "WHERE c.relname IN ('audit_events', 'session_usage', 'caller_charges', "
            "'audit_prunes') ORDER BY 1"
        )
        assert owners == [
            ("audit_events", "sql_warden_owner"),
            ("audit_prunes", "sql_warden_owner"),
            ("caller_charges", "sql_warden_owner"),
            ("session_usage", "sql_warden_owner"),
        ]

    def test_init_runs_again(self, audit: Audit) -> None:
        again = audit.cli("hw_admin", "audit", "init", "--owner", "sql_warden_owner")
        assert again.exit_code == 0, again.output
        assert again.output.startswith("✓ the audit tables at ")
        assert again.output.rstrip().endswith("are up to date, owned by sql_warden_owner")

    def test_nobody_else_makes_tables_there(self, audit: Audit) -> None:
        with (
            psycopg.connect(audit.dsn("hw_warden")) as conn,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            conn.execute("CREATE TABLE public.audit_events_2 (id int)")


POOLS = pytest.mark.parametrize(
    "pool", [None, PoolSettings(max_size=2)], ids=["one connection", "pooled"]
)


class TestTheWriter:
    """The server's role: on pooled connections, as a server has them, the same."""

    @POOLS
    def test_starts_without_changing_the_schema(
        self, audit: Audit, pool: PoolSettings | None
    ) -> None:
        sink = PostgresAuditSink(audit.dsn("hw_warden"), pool=pool)
        try:
            sink.ensure_schema()  # checks rather than applies: it may not
            assert sink.tampering() == ()
        finally:
            sink.close()

    @POOLS
    def test_records_and_keeps_budgets(self, empty: Audit, pool: PoolSettings | None) -> None:
        sink = PostgresAuditSink(empty.dsn("hw_warden"), pool=pool)
        store = sink.session_store("support")
        try:
            sink.record(_event(session_id="s1"))
            assert sink.usage("s1", "support") == Usage(queries=1)
            charge = store.charge("s1", Usage(queries=1), within=BudgetConfig(max_queries=5))
            assert charge.usage == Usage(queries=2)
        finally:
            store.close()
            sink.close()

    @pytest.mark.parametrize(
        "statement",
        [
            "UPDATE audit_events SET decision = 'allowed'",
            "DELETE FROM audit_events",
            "TRUNCATE audit_events",
            "ALTER TABLE audit_events DROP COLUMN reason",
            "DROP TABLE audit_events",
            "DELETE FROM audit_prunes",
        ],
    )
    @POOLS
    def test_cant_change_or_remove_a_record(
        self, empty: Audit, statement: str, pool: PoolSettings | None
    ) -> None:
        sink = PostgresAuditSink(empty.dsn("hw_warden"), pool=pool)
        sink.record(_event(decision="refused", code="TABLE_NOT_ALLOWED"))
        sink.close()
        with (
            psycopg.connect(empty.dsn("hw_warden")) as conn,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            conn.execute(statement)
        assert empty.sql("SELECT decision FROM audit_events") == [("refused",)]

    def test_is_told_to_ask_the_owner_for_a_schema_it_cant_update(self, audit: Audit) -> None:
        audit.sql("ALTER TABLE audit_events DROP COLUMN identity")
        sink = PostgresAuditSink(audit.dsn("hw_warden"))
        try:
            with pytest.raises(AuditError) as excinfo:
                sink.ensure_schema()
            assert str(excinfo.value) == (
                "the audit tables need updating, which "
                "role hw_warden can't do since it doesn't own them (audit_events has no "
                "column identity): run `sql-warden audit init` as their owner"
            )
        finally:
            sink.close()
            fixed = audit.cli("hw_admin", "audit", "init", "--owner", "sql_warden_owner")
            assert fixed.exit_code == 0, fixed.output
        PostgresAuditSink(audit.dsn("hw_warden")).ensure_schema()

    def test_a_role_that_cant_add_records_isnt_one(self, audit: Audit) -> None:
        sink = PostgresAuditSink(audit.dsn("hw_analyst"))
        with pytest.raises(AuditError, match="role hw_analyst can't add records to audit_events"):
            sink.ensure_schema()
        sink.close()


class TestWhatCanTamper:
    def _tampering(self, dsn: str) -> tuple[str, ...] | None:
        sink = PostgresAuditSink(dsn)
        try:
            return sink.tampering()
        finally:
            sink.close()

    def test_the_owner_and_a_superuser(self, audit: Audit) -> None:
        assert self._tampering(audit.dsn("hw_admin")) == (
            "can act as sql_warden_owner, which owns audit_events",
            "can UPDATE, DELETE, TRUNCATE on audit_events",
        )
        assert self._tampering(audit.admin) == ("is a superuser",)

    def test_a_writer_given_one_privilege_too_many(self, audit: Audit) -> None:
        audit.sql("CREATE ROLE hw_extra NOLOGIN")
        audit.sql("GRANT DELETE ON audit_events TO hw_extra")
        audit.sql("CREATE ROLE hw_loose LOGIN PASSWORD 'hw_loose' IN ROLE sql_warden_writer")
        audit.sql("ALTER ROLE hw_loose NOINHERIT")
        audit.sql("GRANT hw_extra TO hw_loose")
        try:
            # It doesn't inherit hw_extra's grant, but SET ROLE would give it.
            assert self._tampering(audit.dsn("hw_loose")) == ("can DELETE on audit_events",)
        finally:
            audit.sql("DROP OWNED BY hw_extra, hw_loose")
            audit.sql("DROP ROLE hw_loose, hw_extra")

    def test_validate_live_says_what_each_can_do(
        self, audit: Audit, warehouse: Any, tmp_path: Path
    ) -> None:
        policy = tmp_path / "warden.yaml"
        policy.write_text(f"version: 1\nwarehouse:\n  dsn: '{warehouse.reader_dsn}'\n")
        args = ["--config", str(policy), "config", "validate", "--live"]

        def validate(dsn: str, append_only: bool = False) -> Any:
            policy.write_text(
                f"version: 1\nwarehouse:\n  dsn: '{warehouse.reader_dsn}'\n"
                f"audit:\n  dsn: '{dsn}'\n  append_only: {str(append_only).lower()}\n"
            )
            return CliRunner().invoke(cli, args, env={"SQL_WARDEN_AUDIT_DSN": None})

        writer = validate(audit.dsn("hw_warden"), append_only=True)
        assert writer.exit_code == 0, writer.output
        assert writer.output.splitlines()[-1] == "  audit:     its role can only add records"
        owner = validate(audit.dsn("hw_admin"))
        assert owner.exit_code == 0, owner.output
        assert owner.output.splitlines()[-3:] == [
            "  audit:     ! its role can change or remove records:",
            "               it can act as sql_warden_owner, which owns audit_events",
            "               it can UPDATE, DELETE, TRUNCATE on audit_events",
        ]
        refused = validate(audit.dsn("hw_admin"), append_only=True)
        assert refused.exit_code == 1
        assert "since audit.append_only is set" in refused.output.splitlines()[-1]


def _seed(audit: Audit) -> None:
    sink = PostgresAuditSink(audit.dsn("hw_warden"))
    for days in (400, 100, 40, 5):
        sink.record(_event(ts=NOW - datetime.timedelta(days=days), session_id=f"d{days}"))
    sink.close()
    audit.sql(
        "INSERT INTO session_usage (profile, session_id, queries, updated_at) VALUES "
        "('support', 'idle', 3, now() - interval '100 days'), "
        "('support', 'active', 1, now() - interval '1 day')"
    )
    audit.sql(
        "INSERT INTO caller_charges (profile, caller, ts, queries) VALUES "
        "('support', 'bot', now() - interval '40 days', 1), "
        "('support', 'bot', now() - interval '20 days', 1)"
    )


class TestPrune:
    def test_removes_what_is_old_and_records_that_it_did(self, empty: Audit) -> None:
        _seed(empty)
        dry = empty.cli("hw_retention", "audit", "prune", "--older-than", "30d", "--dry-run")
        assert dry.exit_code == 0, dry.output
        assert dry.output.splitlines()[0].startswith("would remove 3 audit events recorded before ")
        assert dry.output.splitlines()[0].endswith(
            ", the budgets of 1 sessions idle since then, and 1 caller charges"
        )
        assert empty.sql("SELECT count(*) FROM audit_events") == [(4,)]

        pruned = empty.cli("hw_retention", "audit", "prune", "--older-than", "30d")
        assert pruned.exit_code == 0, pruned.output
        assert pruned.output.splitlines()[-1] == "recorded in audit_prunes"
        assert empty.sql("SELECT session_id FROM audit_events") == [("d5",)]
        assert empty.sql("SELECT session_id FROM session_usage") == [("active",)]
        # A 30-day cutoff leaves 31 days of a caller's charges: their longest window.
        assert empty.sql("SELECT count(*) FROM caller_charges") == [(1,)]
        assert empty.sql(
            "SELECT pruned_by, events, sessions, caller_charges FROM audit_prunes"
        ) == [("hw_retention", 3, 1, 1)]

    def test_the_pruner_reads_no_record_and_can_t_hide_a_prune(self, empty: Audit) -> None:
        _seed(empty)
        assert empty.cli("hw_retention", "audit", "prune", "--older-than", "1d").exit_code == 0
        for statement in [
            "SELECT sql FROM audit_events",
            "UPDATE audit_events SET sql = ''",
            "DELETE FROM audit_prunes",
            "UPDATE audit_prunes SET events = 0",
            "INSERT INTO audit_events (id, ts, dry_run, sql, decision, duration_ms, trace) "
            "VALUES (gen_random_uuid(), now(), false, 'forged', 'allowed', 1, '[]')",
        ]:
            with (
                psycopg.connect(empty.dsn("hw_retention")) as conn,
                pytest.raises(psycopg.errors.InsufficientPrivilege),
            ):
                conn.execute(statement)
        assert empty.sql("SELECT events FROM audit_prunes") == [(4,)]

    def test_the_server_s_role_cannot_prune(self, empty: Audit) -> None:
        _seed(empty)
        refused = empty.cli("hw_warden", "audit", "prune", "--older-than", "30d")
        assert refused.exit_code == 1
        assert "permission denied" in refused.output
        assert empty.sql("SELECT count(*) FROM audit_events") == [(4,)]
        assert empty.sql("SELECT count(*) FROM audit_prunes") == [(0,)]


class TestExport:
    def test_windows_that_meet_export_every_event_once(self, empty: Audit) -> None:
        _seed(empty)

        def export(since: datetime.datetime, until: datetime.datetime) -> list[dict[str, Any]]:
            out = empty.cli(
                "hw_analyst",
                "audit",
                "export",
                "--since",
                since.isoformat(),
                "--until",
                until.isoformat(),
            )
            assert out.exit_code == 0, out.output
            return [json.loads(line) for line in out.stdout.splitlines()]

        middle = NOW - datetime.timedelta(days=50)
        first = export(NOW - datetime.timedelta(days=500), middle)
        second = export(middle, NOW)
        assert [e["session_id"] for e in first] == ["d400", "d100"]
        assert [e["session_id"] for e in second] == ["d40", "d5"]
        assert set(first[0]) >= {"id", "ts", "sql", "decision", "trace", "profile"}

    def test_to_a_file_with_a_count_on_stderr(self, empty: Audit, tmp_path: Path) -> None:
        _seed(empty)
        out = tmp_path / "audit.jsonl"
        ran = empty.cli("hw_analyst", "audit", "export", "--since", "2000-01-01", "-o", str(out))
        assert ran.exit_code == 0, ran.output
        assert len(out.read_text().splitlines()) == 4
        assert ran.stderr.startswith("exported 4 events recorded from 2000-01-01T00:00:00+00:00")

    def test_the_reader_only_reads(self, empty: Audit) -> None:
        with (
            psycopg.connect(empty.dsn("hw_analyst")) as conn,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            conn.execute("DELETE FROM audit_events")
