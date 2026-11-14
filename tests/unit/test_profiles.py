import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from mcp import Client

from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import EXIT_ERROR, cli
from sql_warden.config import DEFAULT_DSN, ConfigError, parse_config
from sql_warden.profiles import Access, Profile, ProfileError, select_profile
from sql_warden.server import create_server
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine

PUBLIC_DSN = "postgresql://warden_public:pw@db/warehouse"
POLICY = f"""\
version: 1
default_profile: public
profiles:
  public:
    dsn: {PUBLIC_DSN}
    tables:
      public.products: [id, name, price_cents]
  admin:
    tables: "*"
"""
PUBLIC_ACCESS = Access({("public", "products"): frozenset({"id", "name", "price_cents"})})


def _config_error(text: str) -> str:
    with pytest.raises(ConfigError) as caught:
        parse_config(text)
    return str(caught.value)


class TestConfig:
    def test_profiles_and_default(self) -> None:
        config = parse_config(POLICY)
        assert config.default_profile == "public"
        assert config.profiles is not None
        assert {name: p.dsn for name, p in config.profiles.items()} == {
            "public": PUBLIC_DSN,
            "admin": None,
        }

    def test_a_profile_dsn_can_come_from_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PUBLIC_DSN", PUBLIC_DSN)
        config = parse_config("version: 1\nprofiles:\n  public:\n    dsn: ${PUBLIC_DSN}\n")
        assert config.profiles is not None
        assert config.profiles["public"].dsn == PUBLIC_DSN

    def test_no_section_means_no_profiles(self) -> None:
        assert parse_config("version: 1").profiles is None

    def test_table_rules(self) -> None:
        config = parse_config(POLICY)
        assert config.profiles is not None
        assert config.profiles["public"].tables == {
            "public.products": ("id", "name", "price_cents")
        }
        assert config.profiles["admin"].tables == "*"

    def test_a_profile_without_tables_reads_nothing(self) -> None:
        config = parse_config("version: 1\nprofiles:\n  public: {}\n")
        assert config.profiles is not None
        assert Access.from_config(config.profiles["public"]) == Access({})

    @pytest.mark.parametrize(
        ("tables", "message"),
        [
            ("all", 'tables must be "*" or a mapping of schema.table to "*" or a list'),
            ("[public.products]", 'tables must be "*" or a mapping'),
            ('{products: "*"}', "'products' must be schema.table, e.g. public.products"),
            ('{a.b.c: "*"}', "'a.b.c' must be schema.table"),
            ("{public.products: id}", 'public.products must be "*" or a list of column names'),
            ("{public.products: []}", "public.products lists no columns; give some"),
            ("{public.products: [id, name, id]}", "public.products lists id more than once"),
        ],
    )
    def test_bad_table_rules(self, tables: str, message: str) -> None:
        assert message in _config_error(f"version: 1\nprofiles:\n  p:\n    tables: {tables}\n")

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("profiles: {}", "profiles: define at least one profile, or leave the section out"),
            ("profiles:\n  all: {}", "'all' is the implicit profile used when none are defined"),
            ("profiles:\n  Public: {}", "profile name 'Public' must be lowercase letters"),
            ("profiles:\n  9lives: {}", "profile name '9lives' must be"),
            ("profiles:\n  a b: {}", "profile name 'a b' must be"),
            ("default_profile: public", "default_profile is 'public', but there is no profiles"),
            (
                "default_profile: nope\nprofiles:\n  public: {}\n  admin: {}",
                "default_profile is 'nope', which is not one of the profiles (public, admin)",
            ),
            ("profiles:\n  public:\n    dsn: [x]", "profiles.public.dsn: Input should be"),
        ],
    )
    def test_problems(self, text: str, message: str) -> None:
        assert message in _config_error(f"version: 1\n{text}\n")

    def test_every_problem_is_reported_at_once(self) -> None:
        message = _config_error(
            "version: 1\nprofiles:\n  public:\n    nope: 1\n  admin:\n    dsn: 3\n"
        )
        assert "profiles.public.nope" in message
        assert "profiles.admin.dsn" in message


class TestSelect:
    def test_without_profiles_there_is_only_the_implicit_one(self) -> None:
        config = parse_config("version: 1")
        expected = Profile("all", DEFAULT_DSN, own_dsn=False, implicit=True)
        assert select_profile(config) == select_profile(config, "all") == expected

    def test_without_profiles_another_name_is_an_error(self) -> None:
        with pytest.raises(ProfileError, match="no profiles are configured, so the only one is"):
            select_profile(parse_config("version: 1"), "public")

    def test_the_default(self) -> None:
        assert select_profile(parse_config(POLICY)) == Profile(
            "public", PUBLIC_DSN, own_dsn=True, access=PUBLIC_ACCESS
        )

    def test_a_profile_without_a_dsn_uses_the_warehouse_dsn(self) -> None:
        assert select_profile(parse_config(POLICY), "admin") == Profile(
            "admin", DEFAULT_DSN, own_dsn=False, access=Access("*")
        )

    def test_an_unknown_name_is_never_a_fallback(self) -> None:
        with pytest.raises(ProfileError, match="unknown profile 'admn': the config defines"):
            select_profile(parse_config(POLICY), "admn")

    def test_no_name_and_no_default(self) -> None:
        config = parse_config("version: 1\nprofiles:\n  public: {}\n  admin: {}\n")
        with pytest.raises(ProfileError, match="no profile picked: pass --profile"):
            select_profile(config)


@pytest.fixture
def policy(isolated_cli: Path) -> Path:
    path = isolated_cli / "warden.yaml"
    path.write_text(POLICY)
    return path


class TestCli:
    def test_the_default_profile_and_its_dsn(self, engines: list[FakeEngine], policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["query", "select 1 as id"])
        assert outcome.exit_code == 0, outcome.output
        assert "(1 row, 1 ms, profile public)" in outcome.output
        assert engines[0].dsn == PUBLIC_DSN

    def test_the_flag_beats_the_environment(self, engines: list[FakeEngine], policy: Path) -> None:
        outcome = CliRunner().invoke(
            cli, ["check", "select 1", "--profile", "admin"], env={"SQL_WARDEN_PROFILE": "public"}
        )
        assert "→ allowed (profile admin; dry run, nothing was executed)" in outcome.output

    def test_the_environment_beats_the_default(
        self, engines: list[FakeEngine], policy: Path
    ) -> None:
        outcome = CliRunner().invoke(
            cli, ["check", "select 1"], env={"SQL_WARDEN_PROFILE": "admin"}
        )
        assert "profile admin" in outcome.output

    def test_dsn_flag_changes_only_profiles_without_their_own(
        self, engines: list[FakeEngine], policy: Path
    ) -> None:
        # A profile's own dsn is part of the policy; --dsn must not widen what it can read.
        runner = CliRunner()
        runner.invoke(cli, ["check", "select 1", "--dsn", "postgresql://other/db"])
        runner.invoke(
            cli, ["check", "select 1", "--dsn", "postgresql://other/db", "--profile", "admin"]
        )
        assert [engine.dsn for engine in engines] == [PUBLIC_DSN, "postgresql://other/db"]

    def test_an_unknown_profile_stops_before_connecting(
        self, engines: list[FakeEngine], policy: Path
    ) -> None:
        outcome = CliRunner().invoke(cli, ["query", "select 1", "--profile", "root"])
        assert outcome.exit_code == EXIT_ERROR
        assert "unknown profile 'root': the config defines public, admin" in outcome.output
        assert engines == []

    def test_refusals_name_the_profile(self, engines: list[FakeEngine], policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["query", "delete from orders"])
        assert outcome.output.splitlines()[-1] == "→ refused by shape (profile public)"

    def test_json_carries_the_profile(self, engines: list[FakeEngine], policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["check", "select 1", "--json", "--profile", "admin"])
        assert json.loads(outcome.output)["profile"] == "admin"

    def test_validate_lists_the_profiles(self, policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["config", "validate"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines()[8:] == [
            "  auth:      none: HTTP needs no token, and is served on loopback only",
            "  profiles:  public (default): connects to db/warehouse as warden_public",
            "               reads public.products (id, name, price_cents)",
            "             admin: connects with warehouse.dsn",
            "               reads every table its role can",
        ]
        assert "pw" not in outcome.output

    def test_validate_says_when_servers_need_a_profile(self, isolated_cli: Path) -> None:
        path = isolated_cli / "warden.yaml"
        path.write_text("version: 1\nprofiles:\n  public: {}\n")
        outcome = CliRunner().invoke(cli, ["config", "validate"])
        assert outcome.output.splitlines()[-1] == (
            "             no default_profile: servers must be given --profile"
        )


@pytest.mark.anyio
@pytest.mark.parametrize("anyio_backend", ["asyncio"])
class TestMcp:
    async def test_results_and_tables_name_the_profile(self, anyio_backend: str) -> None:
        async with Client(
            create_server(Warden(FakeEngine(), audit=MemoryAuditSink(), profile="public"))
        ) as client:
            instructions = client.instructions
            ran = await client.call_tool("run_query", {"sql": "select 1"})
            refused = await client.call_tool("run_query", {"sql": "delete from orders"})
            tables = await client.call_tool("list_tables", {})
        assert instructions is not None
        assert "serves the 'public' profile" in instructions
        for result in (ran, refused, tables):
            assert result.structured_content is not None
            assert result.structured_content["profile"] == "public"

    async def test_without_profiles_the_instructions_say_so(self, anyio_backend: str) -> None:
        async with Client(create_server(Warden(FakeEngine(), audit=MemoryAuditSink()))) as client:
            assert client.instructions is not None
            assert "No access profiles are configured" in client.instructions
