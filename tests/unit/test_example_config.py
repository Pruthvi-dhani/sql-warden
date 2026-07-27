"""The shipped example config must load.

These tests read `demo/config.example.yaml` itself rather than a fixture. An example that
drifts out of sync with the schema is worse than no example -- it is the first thing
anyone copies, and it fails at their startup rather than in our CI.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sql_warden.config import Config, ConfigError
from sql_warden.engines.base import SUPPORTED_COST_UNITS, EngineName

EXAMPLE = Path(__file__).resolve().parents[2] / "demo" / "config.example.yaml"

TARGET_DSN = "postgresql://warden_ro:pw@localhost:5433/warden_target"
AUDIT_DSN = "postgresql://audit_writer:pw@localhost:5434/warden_audit"


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TARGET_DATABASE_URL", TARGET_DSN)
    monkeypatch.setenv("AUDIT_DATABASE_URL", AUDIT_DSN)


def test_the_example_exists() -> None:
    """Guards against the suite passing because the file was renamed or removed."""
    assert EXAMPLE.is_file(), f"missing {EXAMPLE}"


def test_the_example_loads(env: None) -> None:
    config = Config.from_yaml(EXAMPLE)

    assert config.server.engine is EngineName.POSTGRES
    assert config.limits.max_rows == 500
    assert config.target.dsn == TARGET_DSN
    assert config.audit.dsn == AUDIT_DSN


def test_the_example_configures_a_gate_for_every_engine(env: None) -> None:
    """Not required by the schema -- only the *selected* engine needs a gate. But an
    example that omits one leaves whoever switches engines with no cost gate and no error,
    since the omission only becomes fatal once that engine is selected.
    """
    config = Config.from_yaml(EXAMPLE)

    assert set(config.cost_gate) == set(EngineName)
    for engine, gate in config.cost_gate.items():
        assert gate.unit in SUPPORTED_COST_UNITS[engine]


def test_the_example_fails_closed_without_its_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Running the example without its environment must not start a server that writes its
    audit trail nowhere.
    """
    monkeypatch.delenv("TARGET_DATABASE_URL", raising=False)
    monkeypatch.delenv("AUDIT_DATABASE_URL", raising=False)

    with pytest.raises(ConfigError, match="not set"):
        Config.from_yaml(EXAMPLE)


def test_the_example_keeps_audit_out_of_the_target_blast_radius(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The separation is only real if the example demonstrates it. Here the environment is
    deliberately misconfigured to point both at one database, and the example must refuse.
    """
    monkeypatch.setenv("TARGET_DATABASE_URL", TARGET_DSN)
    monkeypatch.setenv("AUDIT_DATABASE_URL", TARGET_DSN)

    with pytest.raises(ConfigError, match="same database"):
        Config.from_yaml(EXAMPLE)
