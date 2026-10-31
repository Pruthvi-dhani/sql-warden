from pathlib import Path

import pytest
from pydantic import ValidationError

from sql_warden.config import (
    DEFAULT_DSN,
    ConfigError,
    WardenConfig,
    default_config,
    describe_dsn,
    load_config,
    parse_config,
)

EXAMPLE_CONFIG = Path(__file__).parents[2] / "warden.example.yaml"


def _error(text: str) -> str:
    with pytest.raises(ConfigError) as caught:
        parse_config(text, source="warden.yaml")
    return str(caught.value)


def test_minimal_config_uses_demo_defaults() -> None:
    config = parse_config("version: 1")
    assert config == default_config()
    assert config.warehouse.dsn == DEFAULT_DSN
    assert (config.warehouse.statement_timeout_ms, config.warehouse.max_rows) == (5_000, 100)
    assert config.warehouse.dialect == "postgres"


def test_full_warehouse_section() -> None:
    config = parse_config(
        """
        version: 1
        warehouse:
          engine: postgres
          dsn: postgresql://u:p@db.internal:5432/sales
          statement_timeout_ms: 250
          max_rows: 10
          connect_timeout_s: 2
        """
    )
    assert config.warehouse.dsn == "postgresql://u:p@db.internal:5432/sales"
    assert config.warehouse.statement_timeout_ms == 250
    assert config.warehouse.max_rows == 10
    assert config.warehouse.connect_timeout_s == 2


def test_example_config_matches_the_demo_stack(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WARDEN_READER_PASSWORD", raising=False)
    assert load_config(EXAMPLE_CONFIG) == default_config()


def test_config_is_immutable() -> None:
    with pytest.raises(ValidationError):
        default_config().warehouse.max_rows = 5  # type: ignore[misc]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("version: 1\nmasks: {}", "masks: Extra inputs are not permitted"),
        (
            "version: 1\nwarehouse:\n  max_row: 5",
            "warehouse.max_row: Extra inputs are not permitted",
        ),
        (
            "version: 1\nwarehouse:\n  max_rows: 0",
            "warehouse.max_rows: Input should be greater than 0",
        ),
        (
            "version: 1\nwarehouse:\n  max_rows: lots",
            "warehouse.max_rows: Input should be a valid integer",
        ),
        ("version: 1\nwarehouse:\n  engine: mysql", "warehouse.engine: Input should be 'postgres'"),
        ("version: 2", "version: Input should be 1"),
        ("warehouse: {}", "version: Field required"),
        ("", "version: Field required"),
    ],
)
def test_invalid_configs_name_the_field_and_problem(text: str, expected: str) -> None:
    message = _error(text)
    assert message.startswith("warden.yaml: invalid config")
    assert expected in message


def test_every_problem_is_reported_at_once() -> None:
    message = _error("version: 3\nwarehouse:\n  max_rows: 0\n  timeout: 5")
    assert "version:" in message
    assert "warehouse.max_rows:" in message
    assert "warehouse.timeout:" in message


def test_yaml_syntax_errors_give_the_line() -> None:
    message = _error("version: 1\nwarehouse:\n  dsn: [unclosed\n")
    assert message.startswith("warden.yaml: invalid YAML (line ")


def test_top_level_must_be_a_mapping() -> None:
    assert _error("- version: 1") == "warden.yaml: the top level must be a mapping of sections"


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="file not found"):
        load_config(tmp_path / "nope.yaml")


class TestEnvInterpolation:
    def test_variable_is_substituted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DB_PASSWORD", "s3cret")
        config = parse_config("version: 1\nwarehouse:\n  dsn: postgresql://u:${DB_PASSWORD}@h/db")
        assert config.warehouse.dsn == "postgresql://u:s3cret@h/db"

    def test_default_is_used_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("DB_HOST", raising=False)
        config = parse_config(
            "version: 1\nwarehouse:\n  dsn: postgresql://${DB_HOST:-localhost}/db"
        )
        assert config.warehouse.dsn == "postgresql://localhost/db"

    def test_set_variable_beats_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DB_HOST", "db.internal")
        config = parse_config(
            "version: 1\nwarehouse:\n  dsn: postgresql://${DB_HOST:-localhost}/db"
        )
        assert config.warehouse.dsn == "postgresql://db.internal/db"

    def test_several_variables_in_one_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("U", "alice")
        monkeypatch.setenv("P", "pw")
        config = parse_config("version: 1\nwarehouse:\n  dsn: postgresql://${U}:${P}@h/db")
        assert config.warehouse.dsn == "postgresql://alice:pw@h/db"

    def test_unset_variable_without_default_is_an_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("DB_PASSWORD", raising=False)
        message = _error("version: 1\nwarehouse:\n  dsn: postgresql://u:${DB_PASSWORD}@h/db")
        assert message == (
            "warden.yaml: environment variable DB_PASSWORD is not set "
            "(referenced as ${DB_PASSWORD})"
        )

    def test_interpolated_values_are_still_validated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ROWS", "0")
        assert "warehouse.max_rows" in _error("version: 1\nwarehouse:\n  max_rows: ${ROWS}")

    def test_non_string_values_are_left_alone(self) -> None:
        assert parse_config("version: 1\nwarehouse:\n  max_rows: 7").warehouse.max_rows == 7


@pytest.mark.parametrize(
    ("dsn", "shown"),
    [
        (
            "postgresql://warden_reader:secret@localhost:5433/warehouse",
            "localhost:5433/warehouse as warden_reader",
        ),
        ("host=db.internal dbname=sales user=bot password=secret", "db.internal/sales as bot"),
        ("postgresql:///warehouse", "localhost/warehouse"),
    ],
)
def test_describe_dsn_never_shows_the_password(dsn: str, shown: str) -> None:
    assert describe_dsn(dsn) == shown
    assert "secret" not in describe_dsn(dsn)


def test_describe_dsn_handles_garbage() -> None:
    assert describe_dsn("not a dsn ===") == "(unparseable connection string)"


def test_model_requires_version_even_from_python() -> None:
    with pytest.raises(ValidationError):
        WardenConfig.model_validate({})
