"""Tests for cost estimates and the enforcement model.

The property under test throughout is that a cost cannot be compared to a number denominated
in something else. plan.md §4.3 calls collapsing estimates into a bare float the design
error to avoid; these tests are what make it unavailable rather than merely discouraged.
"""

from __future__ import annotations

import pytest

from sql_warden.engines.base import (
    CostEstimate,
    CostUnit,
    Enforced,
    EnforcementModel,
    UnitMismatch,
)


def estimate(unit: CostUnit = CostUnit.PLANNER_COST, value: float = 100.0) -> CostEstimate:
    return CostEstimate(unit=unit, value=value, is_pre_execution=True)


# -- unit safety ---------------------------------------------------------------------


def test_comparing_across_units_raises() -> None:
    """The whole point. A Postgres planner cost of 50,000 and a 5 GB byte threshold are
    both floats and mean nothing to each other.
    """
    planner = estimate(CostUnit.PLANNER_COST, 50_000)

    with pytest.raises(UnitMismatch, match="not convertible"):
        planner.exceeds(5_000_000_000, CostUnit.BYTES_SCANNED)


def test_comparing_within_a_unit_works() -> None:
    planner = estimate(CostUnit.PLANNER_COST, 300_000)

    assert planner.exceeds(250_000, CostUnit.PLANNER_COST)
    assert not planner.exceeds(400_000, CostUnit.PLANNER_COST)


def test_the_threshold_is_exclusive_at_the_boundary() -> None:
    """A query costing exactly the limit is allowed. Documented here because "over budget"
    and "at budget" differ by one query at the boundary, and the answer should not depend
    on which comparison operator someone reached for.
    """
    assert not estimate(value=250_000).exceeds(250_000, CostUnit.PLANNER_COST)
    assert estimate(value=250_001).exceeds(250_000, CostUnit.PLANNER_COST)


@pytest.mark.parametrize("unit", list(CostUnit))
def test_every_unit_can_be_compared_against_itself(unit: CostUnit) -> None:
    assert estimate(unit, 10).exceeds(5, unit)


def test_snowflake_units_are_not_interchangeable_with_each_other() -> None:
    """Both belong to Snowflake, and they still do not convert. Bytes and micro-partitions
    answer different questions, and a threshold in one says nothing about the other.
    """
    partitions = estimate(CostUnit.PARTITIONS_SCANNED, 900)

    with pytest.raises(UnitMismatch):
        partitions.exceeds(5_000_000_000, CostUnit.BYTES_SCANNED)


# -- the estimate itself -------------------------------------------------------------


def test_negative_costs_are_rejected() -> None:
    with pytest.raises(ValueError):
        CostEstimate(unit=CostUnit.PLANNER_COST, value=-1, is_pre_execution=True)


def test_estimates_are_immutable() -> None:
    """A cost that a later stage can rewrite is not a gate."""
    cost = estimate()
    with pytest.raises(ValueError):
        cost.value = 0  # type: ignore[misc]  # frozen by design


def test_context_records_what_the_estimate_is_relative_to() -> None:
    """Snowflake plans against the current warehouse and falls back to XSMALL when there is
    none, so the same query yields different numbers under different warehouses.
    """
    cost = CostEstimate(
        unit=CostUnit.BYTES_SCANNED,
        value=1_240_000_000,
        is_pre_execution=True,
        context="warehouse=WARDEN_XS",
    )

    assert cost.context == "warehouse=WARDEN_XS"
    assert estimate().context is None


def test_estimate_serialises_for_the_result_envelope() -> None:
    """plan.md §4.7 puts `cost` in the envelope as unit and value."""
    payload = estimate(CostUnit.BYTES_SCANNED, 1_240_000_000).model_dump(mode="json")

    assert payload["unit"] == "bytes_scanned"
    assert payload["value"] == 1_240_000_000


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValueError):
        CostEstimate(
            unit=CostUnit.PLANNER_COST,
            value=1,
            is_pre_execution=True,
            rows=5,  # type: ignore[call-arg]  # deliberately unknown
        )


# -- enforcement model ---------------------------------------------------------------


def test_enforcement_model_serialises_as_plain_strings() -> None:
    """It goes into the result envelope and into an audit `jsonb` column, so it has to
    survive a round trip through JSON without a `.value` dance.
    """
    model = EnforcementModel(
        readonly=Enforced.NATIVE,
        masking=Enforced.SERVER,
        row_limit=Enforced.SERVER,
        timeout=Enforced.NATIVE,
    )

    assert model.model_dump(mode="json") == {
        "readonly": "native",
        "masking": "server",
        "row_limit": "server",
        "timeout": "native",
    }


def test_enforcement_distinguishes_where_a_control_was_applied() -> None:
    """The claim being recorded is not "masking happened" but "masking happened *here*".

    On Postgres the AST rewrite is the enforcement; on Snowflake a policy attached to the
    column is, and it applies even to queries that never touch sql-warden. Two different
    guarantees, and the audit log has to be able to tell them apart.
    """
    postgres_like = EnforcementModel(
        readonly=Enforced.NATIVE,
        masking=Enforced.SERVER,
        row_limit=Enforced.SERVER,
        timeout=Enforced.NATIVE,
    )
    snowflake_like = EnforcementModel(
        readonly=Enforced.NATIVE,
        masking=Enforced.NATIVE,
        row_limit=Enforced.SERVER,
        timeout=Enforced.NATIVE,
    )

    assert postgres_like.masking is Enforced.SERVER
    assert snowflake_like.masking is Enforced.NATIVE
    assert postgres_like != snowflake_like


def test_every_control_must_be_declared() -> None:
    """No defaults. An engine that forgets to say how it handles timeouts fails to
    construct, rather than quietly reporting the most reassuring answer.
    """
    with pytest.raises(ValueError):
        EnforcementModel(  # type: ignore[call-arg]  # deliberately incomplete
            readonly=Enforced.NATIVE,
            masking=Enforced.SERVER,
            row_limit=Enforced.SERVER,
        )


def test_none_is_available_so_gaps_are_stated_not_implied() -> None:
    """A control nobody enforces should be visible in the audit log as `none`, not absent."""
    model = EnforcementModel(
        readonly=Enforced.NATIVE,
        masking=Enforced.NONE,
        row_limit=Enforced.SERVER,
        timeout=Enforced.NONE,
    )

    assert model.model_dump(mode="json")["masking"] == "none"
