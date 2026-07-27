"""Tests for the engine vocabulary that config validation is built on."""

from __future__ import annotations

import pytest

from sql_warden.engines.base import SUPPORTED_COST_UNITS, CostUnit, EngineName


@pytest.mark.parametrize("engine", list(EngineName))
def test_every_engine_declares_at_least_one_cost_unit(engine: EngineName) -> None:
    """Parametrised over the enum, so adding an engine without declaring its cost units
    fails here rather than at the first query, where the failure would be "cost gate
    silently never fires" -- the worst possible way to learn about it.
    """
    assert engine in SUPPORTED_COST_UNITS, f"{engine} has no entry in SUPPORTED_COST_UNITS"
    assert SUPPORTED_COST_UNITS[engine], f"{engine} declares an empty set of cost units"


def test_supported_units_map_has_no_entries_for_unknown_engines() -> None:
    assert set(SUPPORTED_COST_UNITS) == set(EngineName)


def test_engines_are_string_valued_for_config_and_audit() -> None:
    """`StrEnum` so a member serialises straight into YAML, JSON, and audit rows without
    a `.value` dance at every call site.
    """
    # The annotations are half the assertion: they only typecheck because a StrEnum
    # member *is* a str. The equality then pins the wire value.
    engine: str = EngineName.POSTGRES
    unit: str = CostUnit.BYTES_SCANNED

    assert engine == "postgres"
    assert unit == "bytes_scanned"
    assert f"{EngineName.SNOWFLAKE}" == "snowflake"


def test_unknown_engine_name_is_rejected() -> None:
    """A typo in config must not conjure an engine nobody threat-modelled (plan.md
    decision 10).
    """
    with pytest.raises(ValueError):
        EngineName("postgrez")


def test_postgres_reports_planner_cost_only() -> None:
    assert SUPPORTED_COST_UNITS[EngineName.POSTGRES] == {CostUnit.PLANNER_COST}


def test_snowflake_reports_both_bytes_and_partitions() -> None:
    """`EXPLAIN USING JSON` returns partitions assigned/total and bytes assigned, so both
    are legitimate gates and the choice belongs to the operator (plan.md §4.5).
    """
    assert SUPPORTED_COST_UNITS[EngineName.SNOWFLAKE] == {
        CostUnit.BYTES_SCANNED,
        CostUnit.PARTITIONS_SCANNED,
    }


def test_no_engine_shares_a_cost_unit_with_another() -> None:
    """Two engines reporting the same unit would make a shared threshold look meaningful.
    It would not be: a Postgres planner cost and a Snowflake byte count coincide in type
    and in nothing else. Disjointness keeps that mistake unavailable.
    """
    seen: set[CostUnit] = set()
    for engine, units in SUPPORTED_COST_UNITS.items():
        overlap = seen & units
        assert not overlap, f"{engine} shares {overlap} with another engine"
        seen |= units
