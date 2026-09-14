"""Tests for engine selection.

The registry is the single site where engine identity is consulted (cross-cutting rule 2),
so what matters here is that it stays exhaustive and that an unbuilt engine fails loudly.
These tests are written to keep passing as engines land rather than to be rewritten twice.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sql_warden.config import Config
from sql_warden.engines.base import Engine, EngineName
from sql_warden.engines.registry import (
    EngineNotImplemented,
    build_engine,
    implemented_engines,
)

BASE = {
    "target": {"dsn": "postgresql://warden_ro@localhost:5433/warden_target"},
    "audit": {"dsn": "postgresql://audit_writer@localhost:5434/warden_audit"},
    "limits": {"max_rows": 500, "statement_timeout": "30s"},
    "cost_gate": {
        "postgres": {"planner_cost": 250000},
        "snowflake": {"bytes_scanned": 5_000_000_000},
    },
    "budget": {
        "max_queries_per_session": 50,
        "max_cost_per_session": 50_000_000_000,
        "rate_limit": {"per_fingerprint": 5, "window": "60s"},
    },
    "catalog": {"cache_ttl": "5m"},
}


def config_for(engine: EngineName, tmp_path: Path) -> Config:
    raw = {**BASE, "server": {"engine": engine.value, "policy_file": "./policy.yaml"}}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw))
    return Config.from_yaml(path)


@pytest.mark.parametrize("engine", list(EngineName))
def test_every_engine_either_builds_or_says_which_stage_builds_it(
    engine: EngineName, tmp_path: Path
) -> None:
    """Parametrised over the enum, so this test follows the implementation rather than
    needing to be rewritten when an engine lands: today both raise, and on the day Postgres
    is registered the first branch starts carrying it instead.
    """
    config = config_for(engine, tmp_path)

    if engine in implemented_engines():
        built: Engine = build_engine(config)
        assert built.name is engine
    else:
        with pytest.raises(EngineNotImplemented, match=engine.value):
            build_engine(config)


def test_the_error_names_the_stage_that_will_fix_it(tmp_path: Path) -> None:
    """An operator hitting this needs to know whether to wait or to file a bug."""
    if EngineName.SNOWFLAKE in implemented_engines():
        pytest.skip("Snowflake is implemented; the unbuilt-engine message no longer applies")

    with pytest.raises(EngineNotImplemented, match="Stage 14"):
        build_engine(config_for(EngineName.SNOWFLAKE, tmp_path))


def test_no_engine_is_registered_under_a_name_that_is_not_an_engine() -> None:
    """The registry cannot acquire a key outside the closed enum -- which is what stops a
    typo from conjuring an engine nobody threat-modelled (plan.md decision 10).
    """
    assert implemented_engines() <= frozenset(EngineName)


def test_there_is_no_fallback_engine(tmp_path: Path) -> None:
    """Refusing beats substituting. Quietly falling back to a different database than the
    one configured would mean a policy written for Snowflake enforced against Postgres.
    """
    if implemented_engines() == frozenset(EngineName):
        pytest.skip("every engine is implemented; there is nothing left to fall back from")

    unbuilt = next(e for e in EngineName if e not in implemented_engines())

    with pytest.raises(EngineNotImplemented):
        build_engine(config_for(unbuilt, tmp_path))
