"""Tests for configuration loading and validation.

Every test here is about a control failing *loudly at startup* rather than quietly at
runtime. A cost gate that never fires and a cost gate that does not exist look identical
from inside the process; the difference only shows up on the bill.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
import yaml

from sql_warden.config import Config, ConfigError
from sql_warden.engines.base import CostUnit, EngineName

VALID = {
    "server": {"engine": "postgres", "policy_file": "./policy.yaml"},
    "target": {"dsn": "postgresql://warden_ro@localhost:5433/warden_target"},
    "audit": {"dsn": "postgresql://audit_writer@localhost:5434/warden_audit"},
    "limits": {"max_rows": 500, "statement_timeout": "30s"},
    "cost_gate": {
        "postgres": {"planner_cost": 250000},
        "snowflake": {"bytes_scanned": 5_000_000_000, "partitions_scanned": 1000},
    },
    "budget": {
        "max_queries_per_session": 50,
        "max_cost_per_session": 50_000_000_000,
        "rate_limit": {"per_fingerprint": 5, "window": "60s"},
    },
    "catalog": {"cache_ttl": "5m"},
}


def write(tmp_path: Path, config: object, name: str = "config.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(config))
    return path


def load(tmp_path: Path, **overrides: object) -> Config:
    return Config.from_yaml(write(tmp_path, {**VALID, **overrides}))


# -- happy path ----------------------------------------------------------------------


def test_the_documented_config_shape_loads(tmp_path: Path) -> None:
    config = load(tmp_path)

    assert config.server.engine is EngineName.POSTGRES
    assert config.limits.max_rows == 500
    assert config.limits.statement_timeout == timedelta(seconds=30)
    assert config.budget.rate_limit.window == timedelta(seconds=60)
    assert config.catalog.cache_ttl == timedelta(minutes=5)


def test_active_cost_gates_select_the_configured_engine(tmp_path: Path) -> None:
    config = load(tmp_path)
    assert config.active_cost_gates == {CostUnit.PLANNER_COST: 250000}

    snowflake = load(tmp_path, server={"engine": "snowflake", "policy_file": "./p.yaml"})
    assert snowflake.active_cost_gates == {
        CostUnit.BYTES_SCANNED: 5_000_000_000,
        CostUnit.PARTITIONS_SCANNED: 1000,
    }


def test_yaml_underscore_separated_numbers_parse_as_numbers(tmp_path: Path) -> None:
    """`5_000_000_000` in the documented config is only readable if YAML treats it as an
    int. It does (YAML 1.1), but the config is unusable if that ever changes.
    """
    config = load(tmp_path)
    assert config.budget.max_cost_per_session == 50_000_000_000


# -- durations -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("500ms", timedelta(milliseconds=500)),
        ("30s", timedelta(seconds=30)),
        ("5m", timedelta(minutes=5)),
        ("2h", timedelta(hours=2)),
        (45, timedelta(seconds=45)),
    ],
)
def test_durations_accept_suffixes_and_bare_seconds(
    tmp_path: Path, text: object, expected: timedelta
) -> None:
    config = load(tmp_path, limits={"max_rows": 500, "statement_timeout": text})
    assert config.limits.statement_timeout == expected


@pytest.mark.parametrize("text", ["30", "30 seconds", "5 m", "abc", "-30s", "30d"])
def test_unparseable_durations_are_rejected(tmp_path: Path, text: str) -> None:
    """`"30"` as a string is rejected rather than guessed at. A timeout silently read as
    30 milliseconds instead of 30 seconds is the kind of thing found in production.
    """
    with pytest.raises(ValueError):
        load(tmp_path, limits={"max_rows": 500, "statement_timeout": text})


# -- cost gate -----------------------------------------------------------------------


def test_missing_cost_gate_for_the_selected_engine_is_fatal(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no cost_gate configured"):
        load(tmp_path, cost_gate={"snowflake": {"bytes_scanned": 1}})


def test_cost_gate_in_a_unit_the_engine_cannot_report_is_fatal(tmp_path: Path) -> None:
    """Postgres has no notion of bytes scanned. A threshold expressed in one would parse
    cleanly, look configured, and never fire.
    """
    with pytest.raises(ValueError, match="cannot report cost in"):
        load(tmp_path, cost_gate={"postgres": {"bytes_scanned": 5}})


def test_snowflake_accepts_either_of_its_two_units_alone(tmp_path: Path) -> None:
    for unit in ("bytes_scanned", "partitions_scanned"):
        config = load(
            tmp_path,
            server={"engine": "snowflake", "policy_file": "./p.yaml"},
            cost_gate={"snowflake": {unit: 100}},
        )
        assert set(config.active_cost_gates) == {CostUnit(unit)}


def test_an_engine_can_gate_on_several_units_at_once(tmp_path: Path) -> None:
    """Bytes and partitions catch different problems, and Snowflake reports both from one
    EXPLAIN. A badly filtered scan over a well-clustered table reads modest bytes while
    defeating pruning entirely -- only the partition count shows it, so gating on both
    rejects queries that either alone would wave through.
    """
    config = load(
        tmp_path,
        server={"engine": "snowflake", "policy_file": "./p.yaml"},
        cost_gate={"snowflake": {"bytes_scanned": 5_000_000_000, "partitions_scanned": 1000}},
    )

    assert config.active_cost_gates == {
        CostUnit.BYTES_SCANNED: 5_000_000_000,
        CostUnit.PARTITIONS_SCANNED: 1000,
    }


def test_an_empty_gate_map_for_the_selected_engine_is_fatal(tmp_path: Path) -> None:
    """`postgres: {}` parses as valid YAML and leaves the engine entirely ungated -- the
    same outcome as omitting it, so it fails the same way.
    """
    with pytest.raises(ValueError, match="no cost_gate configured"):
        load(tmp_path, cost_gate={"postgres": {}})


def test_one_bad_unit_among_several_is_still_fatal(tmp_path: Path) -> None:
    """A valid gate alongside an invalid one must not make the invalid one acceptable."""
    with pytest.raises(ValueError, match="cannot report cost in"):
        load(
            tmp_path,
            server={"engine": "snowflake", "policy_file": "./p.yaml"},
            cost_gate={"snowflake": {"bytes_scanned": 1, "planner_cost": 1}},
        )


def test_unknown_engine_key_is_rejected(tmp_path: Path) -> None:
    """A typo must not conjure an engine nobody threat-modelled (plan.md decision 10)."""
    with pytest.raises(ValueError):
        load(tmp_path, cost_gate={"postgrez": {"planner_cost": 1}})


@pytest.mark.parametrize("bad", [0, -1])
def test_non_positive_thresholds_are_rejected(tmp_path: Path, bad: int) -> None:
    with pytest.raises(ValueError):
        load(tmp_path, cost_gate={"postgres": {"planner_cost": bad}})


# -- audit separation ----------------------------------------------------------------


def test_audit_pointing_at_the_target_database_is_fatal(tmp_path: Path) -> None:
    """plan.md §4.9's central claim, checked rather than trusted."""
    dsn = "postgresql://someone@localhost:5433/warden_target"
    with pytest.raises(ValueError, match="same database"):
        load(tmp_path, target={"dsn": dsn}, audit={"dsn": dsn})


def test_audit_separation_ignores_credentials(tmp_path: Path) -> None:
    """The same database reached with a different user is still one blast radius."""
    with pytest.raises(ValueError, match="same database"):
        load(
            tmp_path,
            target={"dsn": "postgresql://reader:pw1@localhost:5433/warden_target"},
            audit={"dsn": "postgresql://writer:pw2@localhost:5433/warden_target"},
        )


def test_different_database_on_the_same_host_is_allowed(tmp_path: Path) -> None:
    """plan.md §4.9 permits a separate database as the minimum bar, so this must load."""
    config = load(
        tmp_path,
        target={"dsn": "postgresql://a@localhost:5433/warden_target"},
        audit={"dsn": "postgresql://b@localhost:5433/warden_audit"},
    )
    assert config.audit.dsn.endswith("warden_audit")


# -- typos and omissions -------------------------------------------------------------


def test_unknown_top_level_key_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load(tmp_path, cost_limit={"max": 1})


def test_mistyped_nested_key_is_rejected(tmp_path: Path) -> None:
    """`max_row` instead of `max_rows` would otherwise leave the row cap at its default
    and the setting you wrote doing nothing.
    """
    with pytest.raises(ValueError):
        load(tmp_path, limits={"max_row": 500, "statement_timeout": "30s"})


def test_missing_section_is_rejected(tmp_path: Path) -> None:
    incomplete = {key: value for key, value in VALID.items() if key != "audit"}
    with pytest.raises(ValueError):
        Config.from_yaml(write(tmp_path, incomplete))


def test_config_is_immutable(tmp_path: Path) -> None:
    """Nothing may raise a limit after startup. mypy rejects this statically thanks to the
    pydantic plugin; the ignore is what lets us prove it also fails at runtime, for the
    code paths types do not reach.
    """
    config = load(tmp_path)
    with pytest.raises(ValueError):
        config.limits.max_rows = 10_000  # type: ignore[misc]  # frozen by design


# -- environment expansion -----------------------------------------------------------


def test_env_references_are_expanded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_DATABASE_URL", "postgresql://a@localhost:5434/warden_audit")

    config = load(tmp_path, audit={"dsn": "${AUDIT_DATABASE_URL}"})

    assert config.audit.dsn == "postgresql://a@localhost:5434/warden_audit"


def test_unset_env_reference_is_fatal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Substituting an empty string would produce a server that starts cleanly and writes
    its audit trail nowhere.
    """
    monkeypatch.delenv("AUDIT_DATABASE_URL", raising=False)

    with pytest.raises(ConfigError, match="not set"):
        load(tmp_path, audit={"dsn": "${AUDIT_DATABASE_URL}"})


def test_non_mapping_yaml_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("- just\n- a list\n")
    with pytest.raises(ConfigError, match="mapping"):
        Config.from_yaml(path)


# -- error reporting -----------------------------------------------------------------


def test_every_config_failure_is_a_single_exception_type(tmp_path: Path) -> None:
    """Field errors surface through Pydantic and cross-field rules through our own
    validators. Both must arrive as `ConfigError`, or a caller has to catch two types
    depending on which check happened to fail first.
    """
    with pytest.raises(ConfigError):
        load(tmp_path, limits={"max_rows": -5, "statement_timeout": "30s"})

    with pytest.raises(ConfigError):
        load(tmp_path, cost_gate={"postgres": {"bytes_scanned": 1}})


def test_errors_name_the_offending_field(tmp_path: Path) -> None:
    """An operator fixing a config needs the path to the problem, not a traceback."""
    with pytest.raises(ConfigError, match=r"limits\.max_rows: .*greater than 0"):
        load(tmp_path, limits={"max_rows": -5, "statement_timeout": "30s"})


def test_multiple_field_errors_are_reported_together(tmp_path: Path) -> None:
    """Fixing config one error per run is a bad afternoon."""
    with pytest.raises(ConfigError) as caught:
        load(
            tmp_path,
            limits={"max_rows": -5, "statement_timeout": "30s"},
            budget={
                "max_queries_per_session": 0,
                "max_cost_per_session": 1,
                "rate_limit": {"per_fingerprint": 5, "window": "60s"},
            },
        )

    message = str(caught.value)
    assert "limits.max_rows" in message
    assert "budget.max_queries_per_session" in message
