from pathlib import Path

from click.testing import CliRunner

from sql_warden.cli import cli
from sql_warden.config import DEFAULT_DSN
from tests.unit.conftest import FakeEngine

CUSTOM = """\
version: 1
warehouse:
  dsn: postgresql://bot:hunter2@db.internal:6000/sales
  statement_timeout_ms: 750
  max_rows: 25
  connect_timeout_s: 3
"""


def _write(path: Path, text: str = CUSTOM) -> Path:
    path.write_text(text)
    return path


def _settings(engine: FakeEngine) -> tuple[str, int, int, int]:
    return engine.dsn, engine.statement_timeout_ms, engine.max_rows, engine.connect_timeout_s


class TestWhichConfigIsUsed:
    def test_no_file_means_demo_defaults(self, engines: list[FakeEngine]) -> None:
        CliRunner().invoke(cli, ["query", "select 1"])
        assert _settings(engines[0]) == (DEFAULT_DSN, 5_000, 100, 5)

    def test_warden_yaml_in_the_current_directory(
        self, engines: list[FakeEngine], isolated_cli: Path
    ) -> None:
        _write(isolated_cli / "warden.yaml")
        CliRunner().invoke(cli, ["query", "select 1"])
        assert _settings(engines[0]) == (
            "postgresql://bot:hunter2@db.internal:6000/sales",
            750,
            25,
            3,
        )

    def test_config_option_beats_warden_yaml(
        self, engines: list[FakeEngine], isolated_cli: Path
    ) -> None:
        _write(isolated_cli / "warden.yaml", "version: 1\nwarehouse:\n  max_rows: 1")
        other = _write(isolated_cli / "other.yaml")
        CliRunner().invoke(cli, ["--config", str(other), "query", "select 1"])
        assert engines[0].max_rows == 25

    def test_config_env_var(self, engines: list[FakeEngine], isolated_cli: Path) -> None:
        path = _write(isolated_cli / "elsewhere.yaml")
        CliRunner().invoke(cli, ["query", "select 1"], env={"SQL_WARDEN_CONFIG": str(path)})
        assert engines[0].max_rows == 25

    def test_flags_override_the_file(self, engines: list[FakeEngine], isolated_cli: Path) -> None:
        _write(isolated_cli / "warden.yaml")
        CliRunner().invoke(
            cli,
            [
                "query",
                "select 1",
                "--max-rows",
                "3",
                "--timeout-ms",
                "99",
                "--dsn",
                "postgresql://x/y",
            ],
        )
        assert _settings(engines[0]) == ("postgresql://x/y", 99, 3, 3)

    def test_dsn_env_var_overrides_the_file(
        self, engines: list[FakeEngine], isolated_cli: Path
    ) -> None:
        _write(isolated_cli / "warden.yaml")
        CliRunner().invoke(
            cli, ["query", "select 1"], env={"SQL_WARDEN_DSN": "postgresql://env/db"}
        )
        assert engines[0].dsn == "postgresql://env/db"
        assert engines[0].max_rows == 25

    def test_check_reads_the_config_too(
        self, engines: list[FakeEngine], isolated_cli: Path
    ) -> None:
        _write(isolated_cli / "warden.yaml")
        assert CliRunner().invoke(cli, ["check", "select 1"]).exit_code == 0
        assert engines[0].max_rows == 25


class TestBrokenConfig:
    def test_invalid_file_stops_the_command_before_any_query(
        self, engines: list[FakeEngine], isolated_cli: Path
    ) -> None:
        _write(isolated_cli / "warden.yaml", "version: 1\nwarehouse:\n  max_rows: 0")
        outcome = CliRunner().invoke(cli, ["query", "select 1"])
        assert outcome.exit_code == 1
        assert "warehouse.max_rows: Input should be greater than 0" in outcome.output
        assert engines == []

    def test_explicit_missing_file_is_an_error(self, engines: list[FakeEngine]) -> None:
        outcome = CliRunner().invoke(cli, ["--config", "missing.yaml", "check", "select 1"])
        assert outcome.exit_code == 1
        assert "missing.yaml: file not found" in outcome.output
        assert engines == []


class TestValidate:
    def test_valid_file_shows_a_summary_without_the_password(self, isolated_cli: Path) -> None:
        path = _write(isolated_cli / "policy.yaml")
        outcome = CliRunner().invoke(cli, ["config", "validate", str(path)])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines() == [
            f"✓ {path} is valid",
            "  warehouse: postgres at db.internal:6000/sales as bot",
            "             statement timeout 750 ms, max 25 rows",
        ]
        assert "hunter2" not in outcome.output

    def test_defaults_to_warden_yaml(self, isolated_cli: Path) -> None:
        _write(isolated_cli / "warden.yaml")
        outcome = CliRunner().invoke(cli, ["config", "validate"])
        assert outcome.exit_code == 0
        assert outcome.output.startswith("✓ warden.yaml is valid")

    def test_uses_the_config_option(self, isolated_cli: Path) -> None:
        path = _write(isolated_cli / "p.yaml")
        outcome = CliRunner().invoke(cli, ["--config", str(path), "config", "validate"])
        assert outcome.exit_code == 0
        assert outcome.output.startswith(f"✓ {path} is valid")

    def test_invalid_file_lists_every_problem(self, isolated_cli: Path) -> None:
        path = _write(isolated_cli / "bad.yaml", "version: 2\nwarehouse:\n  max_row: 5")
        outcome = CliRunner().invoke(cli, ["config", "validate", str(path)])
        assert outcome.exit_code == 1
        assert "version: Input should be 1" in outcome.output
        assert "warehouse.max_row: Extra inputs are not permitted" in outcome.output

    def test_nothing_to_validate(self) -> None:
        outcome = CliRunner().invoke(cli, ["config", "validate"])
        assert outcome.exit_code == 1
        assert "no config file to validate" in outcome.output

    def test_validate_never_connects(self, isolated_cli: Path) -> None:
        # A DSN nothing listens on: validation is about the file, not the database.
        path = _write(
            isolated_cli / "p.yaml", "version: 1\nwarehouse:\n  dsn: postgresql://127.0.0.1:1/x"
        )
        assert CliRunner().invoke(cli, ["config", "validate", str(path)]).exit_code == 0
