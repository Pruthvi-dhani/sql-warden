"""The look at a role before serving with it, against real Postgres roles and grants."""

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import psycopg
import pytest
from click.testing import CliRunner
from psycopg.conninfo import make_conninfo

from sql_warden import cli as cli_module
from sql_warden.cli import ONLY_READERS, cli
from sql_warden.engines import RoleReport
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.profiles import Access
from sql_warden.startup import check_role
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration

# Three roles that can each write in their own way, and what goes with them.
SETUP = """
    CREATE SCHEMA startup_test;
    CREATE SEQUENCE startup_test.counter;
    CREATE TABLE startup_test.notes (id int, body text);

    CREATE ROLE st_writer LOGIN PASSWORD 'st_writer';
    GRANT USAGE ON SCHEMA public TO st_writer;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO st_writer;
    GRANT INSERT, DELETE ON orders TO st_writer;
    GRANT UPDATE (name) ON products TO st_writer;
    GRANT USAGE, CREATE ON SCHEMA startup_test TO st_writer;
    GRANT UPDATE ON SEQUENCE startup_test.counter TO st_writer;
    GRANT CREATE ON DATABASE warehouse TO st_writer;
    GRANT pg_write_server_files TO st_writer;

    CREATE ROLE st_cleaners;
    GRANT USAGE ON SCHEMA public TO st_cleaners;
    GRANT TRUNCATE ON products TO st_cleaners;
    CREATE ROLE st_member LOGIN NOINHERIT PASSWORD 'st_member';
    GRANT USAGE ON SCHEMA public TO st_member;
    GRANT SELECT ON products TO st_member;
    GRANT st_cleaners TO st_member;

    CREATE ROLE st_hidden LOGIN PASSWORD 'st_hidden';
    GRANT INSERT ON startup_test.notes TO st_hidden;
"""
TEARDOWN = """
    DROP SCHEMA startup_test CASCADE;
    DROP OWNED BY st_writer, st_cleaners, st_member, st_hidden;
    DROP ROLE st_writer, st_cleaners, st_member, st_hidden;
"""


@pytest.fixture(scope="module")
def roles(warehouse: Warehouse) -> Iterator[None]:
    with psycopg.connect(warehouse.admin_dsn, autocommit=True) as conn:
        conn.execute(SETUP)
    try:
        yield
    finally:
        with psycopg.connect(warehouse.admin_dsn, autocommit=True) as conn:
            conn.execute(TEARDOWN)


def _as(warehouse: Warehouse, role: str) -> str:
    """The warehouse's connection string for a role whose password is its name."""
    return make_conninfo(warehouse.reader_dsn, user=role, password=role)


class TestRoleReport:
    def test_the_readers_can_only_read(self, warehouse: Warehouse) -> None:
        assert PostgresEngine(warehouse.reader_dsn).role() == RoleReport("warden_reader")
        assert PostgresEngine(warehouse.public_dsn).role() == RoleReport("warden_public")

    def test_the_admin_is_a_superuser(self, warehouse: Warehouse) -> None:
        report = PostgresEngine(warehouse.admin_dsn).role()
        assert report == RoleReport("warehouse_admin", ("is a superuser",))
        assert not report.read_only

    def test_every_way_a_role_can_write(self, warehouse: Warehouse, roles: None) -> None:
        report = PostgresEngine(_as(warehouse, "st_writer")).role()
        assert report.role == "st_writer"
        assert report.writes == (
            "can write files on the database server, as a member of pg_write_server_files",
            "can create schemas in database warehouse",
            "can create tables in schema startup_test",
            "can INSERT, DELETE on public.orders",
            "can UPDATE on public.products",  # a grant on one column is enough
            "can reset sequence startup_test.counter",
        )

    def test_what_a_role_could_do_after_set_role(self, warehouse: Warehouse, roles: None) -> None:
        # st_member doesn't inherit st_cleaners' grants, but SET ROLE would give it them.
        dsn = _as(warehouse, "st_member")
        with psycopg.connect(dsn) as conn:
            can = conn.execute("SELECT has_table_privilege('products', 'TRUNCATE')").fetchone()
        assert can == (False,)
        assert PostgresEngine(dsn).role().writes == (
            "can TRUNCATE on public.products, as a member of st_cleaners",
        )

    def test_a_grant_in_a_schema_the_role_cant_use_is_not_a_way_to_write(
        self, warehouse: Warehouse, roles: None
    ) -> None:
        dsn = _as(warehouse, "st_hidden")
        with psycopg.connect(dsn) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO startup_test.notes VALUES (1, 'x')")
        assert PostgresEngine(dsn).role() == RoleReport("st_hidden")

    def test_looking_changes_nothing_and_needs_no_write_access(self, warehouse: Warehouse) -> None:
        # warden_reader's transactions are read-only by default, and so is the engine's.
        engine = PostgresEngine(warehouse.reader_dsn, statement_timeout_ms=2_000)
        assert engine.role().read_only


class TestCheckRole:
    def test_a_role_granted_just_what_its_profile_allows(self, warehouse: Warehouse) -> None:
        access = Access({("public", "products"): frozenset({"id", "name", "price_cents"})})
        check = check_role(PostgresEngine(warehouse.public_dsn), access)
        assert (check.can_write, check.beyond) == (False, ())

    def test_a_role_that_reads_more_than_its_profile(self, warehouse: Warehouse) -> None:
        access = Access(
            {
                ("public", "products"): frozenset({"id", "name", "price_cents"}),
                ("public", "orders"): "*",
                ("public", "customers"): "*",
            }
        )
        check = check_role(PostgresEngine(warehouse.reader_dsn), access)
        assert not check.can_write
        assert sorted(check.beyond) == [
            "column category of public.products",
            "table public.employee_salaries",
        ]


class Served:
    def __init__(self) -> None:
        self.profiles: list[str] = []

    def create_server(self, warden: Any) -> "Served":
        self.profiles.append(warden.profile)
        return self

    def run(self, transport: str) -> None:
        pass


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch) -> Served:
    """Stops `serve` where it would start answering, and says whether it got there."""
    served = Served()
    monkeypatch.setattr(cli_module, "create_server", served.create_server)
    return served


class TestServe:
    def test_it_starts_as_the_reader(self, warehouse: Warehouse, served: Served) -> None:
        outcome = CliRunner().invoke(cli, ["serve", "--dsn", warehouse.reader_dsn])
        assert (outcome.exit_code, outcome.output) == (0, "")
        assert served.profiles == ["all"]

    def test_it_does_not_start_as_the_superuser(self, warehouse: Warehouse, served: Served) -> None:
        outcome = CliRunner().invoke(cli, ["serve", "--dsn", warehouse.admin_dsn])
        assert outcome.exit_code == 1
        lines = outcome.output.splitlines()
        assert lines[0].startswith("Error: profile all: role warehouse_admin can change the")
        assert lines[1:] == ["  it is a superuser", ONLY_READERS]
        assert "warehouse_admin:warehouse_admin" not in outcome.output  # never the password
        assert served.profiles == []

    def test_it_does_not_start_as_a_role_with_a_grant_that_writes(
        self, warehouse: Warehouse, roles: None, served: Served
    ) -> None:
        outcome = CliRunner().invoke(cli, ["serve", "--dsn", _as(warehouse, "st_member")])
        assert outcome.exit_code == 1
        assert outcome.output.splitlines()[1] == (
            "  it can TRUNCATE on public.products, as a member of st_cleaners"
        )
        assert served.profiles == []

    def test_it_does_not_start_while_the_warehouse_cant_be_asked(self, served: Served) -> None:
        outcome = CliRunner().invoke(
            cli, ["serve", "--dsn", "postgresql://nobody:hunter2@127.0.0.1:1/none"]
        )
        assert outcome.exit_code == 1
        assert outcome.output.startswith(
            "Error: profile all: could not check what its role can do in the warehouse "
            "(127.0.0.1:1/none as nobody): could not connect to the database"
        )
        assert outcome.output.splitlines()[-1] == ONLY_READERS
        assert "hunter2" not in outcome.output
        assert served.profiles == []


@pytest.fixture
def policy(warehouse: Warehouse, audit_dsn: str, tmp_path: Path) -> Path:
    path = tmp_path / "warden.yaml"
    path.write_text(
        f"version: 1\nwarehouse:\n  dsn: {warehouse.reader_dsn}\n"
        f"audit:\n  dsn: {audit_dsn}\n"
        f"default_profile: public\nprofiles:\n"
        f"  public:\n    dsn: {warehouse.public_dsn}\n"
        f"    tables:\n      public.products: [id, name, price_cents]\n"
        f'  support:\n    tables:\n      public.customers: "*"\n      public.orders: "*"\n'
        f'      public.products: "*"\n'
        f'  admin:\n    tables: "*"\n'
    )
    return path


class TestValidateLive:
    def test_every_profiles_role(self, policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["config", "validate", str(policy), "--live"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines()[-5:] == [
            "  live:      public: role warden_public can only read",
            "             support: role warden_reader can only read",
            "               ! but more than the profile allows:",
            "                 table public.employee_salaries",
            "             admin: role warden_reader can only read",
        ]

    def test_a_profile_whose_role_can_write_fails_it(
        self, policy: Path, warehouse: Warehouse
    ) -> None:
        policy.write_text(
            policy.read_text() + f'  root:\n    dsn: {warehouse.admin_dsn}\n    tables: "*"\n'
        )
        outcome = CliRunner().invoke(cli, ["config", "validate", str(policy), "--live"])
        assert outcome.exit_code == 1
        assert outcome.output.splitlines()[-3:] == [
            "             root: ✗ role warehouse_admin can change the warehouse",
            "               it is a superuser",
            f"Error: a server would not start for every profile. {ONLY_READERS}",
        ]
        assert "warehouse_admin:warehouse_admin" not in outcome.output
