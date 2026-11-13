"""The look a server takes at its database role before it starts: a role that can write is
refused, and one that can read more than its profile allows is warned about."""

from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sql_warden import cli as cli_module
from sql_warden.audit import AuditError
from sql_warden.cli import ONLY_READERS, cli
from sql_warden.engines import Column, EngineUnavailable, RoleReport, Table
from sql_warden.engines.postgres import role_writes
from sql_warden.profiles import Access
from sql_warden.startup import RoleCheck, beyond_profile, check_role, listed
from tests.unit.conftest import PRODUCTS, AuditSinks, FakeEngine

CUSTOMERS = Table(
    "public",
    "customers",
    (Column("id", "integer"), Column("email", "text"), Column("ssn", "text")),
)
SALARIES = Table("public", "employee_salaries", (Column("id", "integer"),))
READABLE = (PRODUCTS, CUSTOMERS, SALARIES)
SUPERUSER = RoleReport("warehouse_admin", ("is a superuser",))
WRITER = RoleReport("app_rw", tuple(f"can INSERT on public.t{n}" for n in range(1, 9)))


class TestBeyondProfile:
    def test_a_profile_that_allows_everything_has_nothing_beyond_it(self) -> None:
        assert beyond_profile(READABLE, Access("*")) == ()

    def test_no_profile_at_all_has_nothing_beyond_it(self) -> None:
        assert beyond_profile(READABLE, None) == ()

    def test_tables_the_profile_does_not_list(self) -> None:
        access = Access({("public", "products"): "*", ("public", "customers"): "*"})
        assert beyond_profile(READABLE, access) == ("table public.employee_salaries",)

    def test_columns_the_profile_leaves_out(self) -> None:
        access = Access(
            {
                ("public", "products"): frozenset({"id"}),
                ("public", "customers"): frozenset({"id"}),
                ("public", "employee_salaries"): frozenset({"id"}),
            }
        )
        assert beyond_profile(READABLE, access) == (
            "column name of public.products",
            "columns email, ssn of public.customers",
        )

    def test_a_role_granted_just_what_the_profile_allows(self) -> None:
        access = Access({("public", "products"): frozenset({"id", "name"})})
        assert beyond_profile((PRODUCTS,), access) == ()

    def test_a_profile_that_allows_nothing(self) -> None:
        assert beyond_profile((PRODUCTS,), Access({})) == ("table public.products",)

    def test_names_are_compared_as_stored(self) -> None:
        # Snowflake's are upper case, and so is the profile that names them.
        table = Table("PUBLIC", "PRODUCTS", (Column("ID", "NUMBER"), Column("NAME", "TEXT")))
        access = Access({("PUBLIC", "PRODUCTS"): frozenset({"ID"})})
        assert beyond_profile((table,), access) == ("column NAME of PUBLIC.PRODUCTS",)


class TestCheckRole:
    def test_a_reader_within_its_profile(self) -> None:
        check = check_role(FakeEngine(), Access({("public", "products"): "*"}))
        assert check == RoleCheck(RoleReport("fake_reader"))
        assert not check.can_write

    def test_a_reader_that_reads_more_than_its_profile(self) -> None:
        check = check_role(FakeEngine(catalog=READABLE), Access({("public", "products"): "*"}))
        assert check.beyond == ("table public.customers", "table public.employee_salaries")
        assert not check.can_write

    def test_a_writer_is_not_asked_what_it_reads(self) -> None:
        class NoCatalog(FakeEngine):
            def tables(self) -> tuple[Table, ...]:
                raise AssertionError("not needed: this role won't be served")

        check = check_role(NoCatalog(report=SUPERUSER), Access({}))
        assert (check.can_write, check.beyond) == (True, ())

    def test_a_database_that_cant_be_asked(self) -> None:
        down = EngineUnavailable("could not connect to the database")
        with pytest.raises(EngineUnavailable):
            check_role(FakeEngine(error=down), None)


def test_a_long_list_is_cut_short_and_counted() -> None:
    assert listed(["a", "b"], prefix="it ") == ["it a", "it b"]
    assert listed("abcdefg", shown=5) == ["a", "b", "c", "d", "e", "and 2 more"]


class TestPostgresRoleWrites:
    """What PostgresEngine makes of its two queries' rows; the queries themselves run in
    tests/integration."""

    def test_a_reader(self) -> None:
        assert role_writes([("warden_reader", False, True)]) == ()

    def test_a_superuser_needs_no_list(self) -> None:
        members = [("warehouse_admin", True, True), ("warden_reader", False, False)]
        assert role_writes(members) == ("is a superuser",)

    def test_a_member_of_a_superuser(self) -> None:
        members = [("app", False, True), ("root", True, False)]
        assert role_writes(members) == ("is a member of root, a superuser",)

    def test_roles_that_reach_the_servers_files(self) -> None:
        members = [
            ("app", False, True),
            ("pg_execute_server_program", False, False),
            ("pg_write_server_files", False, False),
        ]
        assert role_writes(members) == (
            "can run programs on the database server, as a member of pg_execute_server_program",
            "can write files on the database server, as a member of pg_write_server_files",
        )

    def test_each_kind_of_grant(self) -> None:
        grants = [
            ("app", True, "database", "warehouse", ["CREATE"]),
            ("app", True, "schema", "public", ["CREATE"]),
            ("app", True, "table", "public.orders", ["INSERT", "UPDATE"]),
            ("app", True, "sequence", "public.orders_id_seq", ["UPDATE"]),
        ]
        assert role_writes([("app", False, True)], grants) == (
            "can create schemas in database warehouse",
            "can create tables in schema public",
            "can INSERT, UPDATE on public.orders",
            "can reset sequence public.orders_id_seq",
        )

    def test_a_privilege_is_reported_once_not_again_for_the_role_it_came_from(self) -> None:
        members = [("app", False, True), ("writers", False, False)]
        grants = [
            ("app", True, "table", "public.orders", ["INSERT", "UPDATE"]),
            ("writers", False, "table", "public.orders", ["INSERT", "UPDATE"]),
        ]
        assert role_writes(members, grants) == ("can INSERT, UPDATE on public.orders",)

    def test_what_it_would_have_only_after_set_role(self) -> None:
        # A member that doesn't inherit: it has INSERT itself, and DELETE as the other role.
        members = [("app", False, True), ("cleaners", False, False)]
        grants = [
            ("app", True, "table", "public.orders", ["INSERT"]),
            ("cleaners", False, "table", "public.orders", ["INSERT", "DELETE"]),
            ("cleaners", False, "table", "public.products", ["TRUNCATE"]),
        ]
        assert role_writes(members, grants) == (
            "can INSERT on public.orders",
            "can DELETE on public.orders, as a member of cleaners",
            "can TRUNCATE on public.products, as a member of cleaners",
        )


class Served:
    """What `serve` got as far as: the server it built, if it built one."""

    def __init__(self) -> None:
        self.profiles: list[str] = []

    def create_server(self, warden: Any) -> "Served":
        self.profiles.append(warden.profile)
        return self

    def run(self, transport: str) -> None:
        pass


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch, audit_sinks: AuditSinks) -> Served:
    served = Served()
    monkeypatch.setattr(cli_module, "create_server", served.create_server)
    return served


def _engine(monkeypatch: pytest.MonkeyPatch, **settings: Any) -> None:
    """Make the CLI's engine one that reports this."""
    monkeypatch.setattr(cli_module, "PostgresEngine", lambda dsn, **_: FakeEngine(dsn, **settings))


POLICY = """
version: 1
warehouse:
  dsn: postgresql://warden_reader:hunter2@db.internal:5432/warehouse
default_profile: public
profiles:
  public:
    dsn: postgresql://warden_public:hunter3@db.internal:5432/warehouse
    tables:
      public.products: [id, name]
  support:
    tables:
      public.products: "*"
  admin:
    tables: "*"
"""


@pytest.fixture
def policy(tmp_path: Path) -> str:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY)
    return str(path)


class TestServe:
    def test_a_reader_is_served(self, served: Served, monkeypatch: pytest.MonkeyPatch) -> None:
        _engine(monkeypatch)
        outcome = CliRunner().invoke(cli, ["serve"])
        assert (outcome.exit_code, outcome.output) == (0, "")
        assert served.profiles == ["all"]

    def test_a_role_that_can_write_is_not(
        self, served: Served, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _engine(monkeypatch, report=SUPERUSER)
        outcome = CliRunner().invoke(
            cli, ["serve", "--dsn", "postgresql://warehouse_admin:hunter2@db.internal/warehouse"]
        )
        assert outcome.exit_code == 1
        assert outcome.output.splitlines() == [
            "Error: profile all: role warehouse_admin can change the warehouse "
            "(db.internal/warehouse as warehouse_admin):",
            "  it is a superuser",
            ONLY_READERS,
        ]
        assert "hunter2" not in outcome.output
        assert served.profiles == []

    def test_a_long_list_of_grants_is_cut_short(
        self, served: Served, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _engine(monkeypatch, report=WRITER)
        outcome = CliRunner().invoke(cli, ["serve"])
        assert outcome.exit_code == 1
        assert outcome.output.splitlines()[1:-1] == [
            "  it can INSERT on public.t1",
            "  it can INSERT on public.t2",
            "  it can INSERT on public.t3",
            "  it can INSERT on public.t4",
            "  it can INSERT on public.t5",
            "  and 3 more",
        ]

    def test_a_warehouse_that_cant_be_asked_is_not_served(
        self, served: Served, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _engine(monkeypatch, error=EngineUnavailable("could not connect to the database"))
        outcome = CliRunner().invoke(cli, ["serve"])
        assert outcome.exit_code == 1
        assert outcome.output.splitlines() == [
            "Error: profile all: could not check what its role can do in the warehouse "
            "(localhost:5433/warehouse as warden_reader): could not connect to the database",
            ONLY_READERS,
        ]
        assert served.profiles == []

    def test_the_audit_database_still_comes_first(
        self, served: Served, audit_sinks: AuditSinks, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _engine(monkeypatch, report=SUPERUSER)
        audit_sinks.fail_with = AuditError("connection refused")
        outcome = CliRunner().invoke(cli, ["serve"])
        assert outcome.output.startswith("Error: audit database at ")

    def test_a_role_that_reads_more_than_its_profile_is_served_with_a_warning(
        self, served: Served, policy: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _engine(monkeypatch, catalog=READABLE)
        outcome = CliRunner().invoke(cli, ["--config", policy, "serve"])
        assert outcome.exit_code == 0
        assert outcome.stderr.splitlines() == [
            "warning: profile public allows less than its role can read. fake_reader can "
            "also read:",
            "  table public.customers",
            "  table public.employee_salaries",
            "Only the access check keeps the profile from these. Give the profile a dsn of "
            "its own, for a role granted just what the profile allows.",
        ]
        assert outcome.stdout == ""  # stdout is the MCP channel
        assert served.profiles == ["public"]

    def test_a_profile_that_allows_everything_has_no_warning(
        self, served: Served, policy: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _engine(monkeypatch, catalog=READABLE)
        outcome = CliRunner().invoke(cli, ["--config", policy, "serve", "--profile", "admin"])
        assert (outcome.exit_code, outcome.output) == (0, "")

    @pytest.mark.parametrize("command", [["query", "select 1"], ["check", "select 1"], ["tables"]])
    def test_commands_run_by_hand_are_not_held_to_it(
        self, audit_sinks: AuditSinks, monkeypatch: pytest.MonkeyPatch, command: list[str]
    ) -> None:
        # Whoever runs them has the connection string anyway: the server is the boundary.
        _engine(monkeypatch, report=SUPERUSER)
        assert CliRunner().invoke(cli, command).exit_code == 0


class TestValidateLive:
    def test_without_the_flag_nothing_connects(
        self, policy: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def no_engine(dsn: str, **_: Any) -> FakeEngine:
            raise AssertionError("config validate doesn't connect")

        monkeypatch.setattr(cli_module, "PostgresEngine", no_engine)
        outcome = CliRunner().invoke(cli, ["config", "validate", policy])
        assert outcome.exit_code == 0
        assert "live:" not in outcome.output

    def test_every_profiles_role_is_checked(
        self, policy: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = []

        def engine(dsn: str, **_: Any) -> FakeEngine:
            built.append(dsn)
            role = "warden_public" if "warden_public" in dsn else "warden_reader"
            return FakeEngine(dsn, catalog=READABLE, report=RoleReport(role))

        monkeypatch.setattr(cli_module, "PostgresEngine", engine)
        outcome = CliRunner().invoke(cli, ["config", "validate", policy, "--live"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines()[-9:] == [
            "  live:      public: role warden_public can only read",
            "               ! but more than the profile allows:",
            "                 table public.customers",
            "                 table public.employee_salaries",
            "             support: role warden_reader can only read",
            "               ! but more than the profile allows:",
            "                 table public.customers",
            "                 table public.employee_salaries",
            "             admin: role warden_reader can only read",
        ]
        assert [dsn.split(":")[1] for dsn in built] == [
            "//warden_public",
            "//warden_reader",
            "//warden_reader",
        ]
        assert "hunter" not in outcome.output

    def test_a_role_that_can_write_fails_it(
        self, policy: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def engine(dsn: str, **_: Any) -> FakeEngine:
            if "warden_public" in dsn:
                return FakeEngine(dsn, report=RoleReport("warden_public"))
            return FakeEngine(dsn, report=SUPERUSER)

        monkeypatch.setattr(cli_module, "PostgresEngine", engine)
        outcome = CliRunner().invoke(cli, ["config", "validate", policy, "--live"])
        assert outcome.exit_code == 1
        assert outcome.output.splitlines()[-6:] == [
            "  live:      public: role warden_public can only read",
            "             support: ✗ role warehouse_admin can change the warehouse",
            "               it is a superuser",
            "             admin: ✗ role warehouse_admin can change the warehouse",
            "               it is a superuser",
            f"Error: a server would not start for every profile. {ONLY_READERS}",
        ]

    def test_a_warehouse_that_cant_be_reached_fails_it(
        self, policy: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        down = EngineUnavailable("could not connect to the database: refused\nIs it running?")
        _engine(monkeypatch, error=down)
        outcome = CliRunner().invoke(cli, ["config", "validate", policy, "--live"])
        assert outcome.exit_code == 1
        assert outcome.output.splitlines()[-4] == (
            "  live:      public: ✗ could not check its role: could not connect to the "
            "database: refused"
        )

    def test_with_no_profiles_the_implicit_one_is_checked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "bare.yaml"
        path.write_text("version: 1\n")
        _engine(monkeypatch, catalog=READABLE)
        outcome = CliRunner().invoke(cli, ["config", "validate", str(path), "--live"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines()[-1] == "  live:      all: role fake_reader can only read"
