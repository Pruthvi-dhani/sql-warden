"""The engine seam.

Everything that differs between databases is declared here and implemented in a sibling
module. The pipeline reads these declarations; it never asks which engine it is talking to.

Design note (plan.md §4.3): a cost estimate is meaningless without its unit. A Postgres
planner cost of 50,000 and 4 GB scanned in Snowflake are not comparable, so there is no
single `max_cost` anywhere in this project -- thresholds are configured per engine, in that
engine's own unit, and validated against what the engine can actually report.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Final

from pydantic import Field

from sql_warden.models import FrozenModel


class EngineName(StrEnum):
    """The engines sql-warden implements and has threat-modelled.

    Deliberately a closed enum rather than an open string. plan.md decision 10: adding a
    third engine requires threat-modelling it, because the dangerous-function list is not
    inheritable. An engine nobody threat-modelled is the worst failure mode a security tool
    has, so a typo in config must not be able to conjure one into existence.
    """

    POSTGRES = "postgres"
    SNOWFLAKE = "snowflake"


class CostUnit(StrEnum):
    """The unit a pre-execution cost estimate is denominated in.

    These are not interchangeable and no conversion between them exists or should exist.
    """

    #: Postgres `EXPLAIN` total cost. Unitless, arbitrary scale, comparable only to itself.
    PLANNER_COST = "planner_cost"

    #: Snowflake bytes assigned for scanning.
    BYTES_SCANNED = "bytes_scanned"

    #: Snowflake micro-partitions assigned. A better proxy than bytes for whether pruning
    #: actually worked, which is the thing that drives warehouse spend.
    PARTITIONS_SCANNED = "partitions_scanned"


#: Which units each engine can actually report.
#:
#: Snowflake's `EXPLAIN USING JSON` returns both partitions and bytes assigned, so either
#: is a legitimate gate; the choice is an operator's, made in config. Postgres has exactly
#: one. Config validation checks the configured unit against this map at load time, so a
#: threshold expressed in a unit the engine cannot produce fails at startup rather than
#: silently never firing.
#:
#: This lives as a static mapping rather than on the `Engine` protocol because config is
#: validated *before* an engine instance exists -- `build_engine()` needs a valid config to
#: run at all. Stage 2's conformance suite asserts each engine's reported unit is a member
#: of its own entry here, so the two cannot drift apart.
SUPPORTED_COST_UNITS: Final[Mapping[EngineName, frozenset[CostUnit]]] = {
    EngineName.POSTGRES: frozenset({CostUnit.PLANNER_COST}),
    EngineName.SNOWFLAKE: frozenset({CostUnit.BYTES_SCANNED, CostUnit.PARTITIONS_SCANNED}),
}


class UnitMismatch(TypeError):
    """Raised when two costs in different units are compared.

    A programming error, never a user-facing one. If this escapes, a threshold was checked
    against a number that does not mean what the threshold means -- which is precisely the
    failure the whole unit-carrying design exists to make impossible.
    """


class CostEstimate(FrozenModel):
    """What a query is predicted to cost, in the engine's own terms."""

    unit: CostUnit
    value: float = Field(ge=0)

    #: Whether this was obtained without spending the resource being measured. Postgres
    #: EXPLAIN and Snowflake EXPLAIN are both pre-execution; a post-hoc figure read after
    #: the fact is not a gate, it is a receipt.
    is_pre_execution: bool

    #: What the estimate is relative to, when that matters. Snowflake builds an EXPLAIN
    #: plan against the current warehouse and falls back to XSMALL when there is none, so
    #: the same query yields different numbers under different warehouses. Recording it is
    #: the difference between a reproducible threshold and a number nobody can reconstruct.
    context: str | None = None

    def exceeds(self, threshold: float, unit: CostUnit) -> bool:
        """Compare against a threshold, refusing to compare across units.

        The unit argument is not redundant. Passing it forces every comparison site to say
        which unit it believes it is working in, so a Postgres planner cost can never be
        silently measured against a byte count.
        """
        if self.unit is not unit:
            raise UnitMismatch(
                f"cannot compare a cost in {self.unit.value!r} against a threshold in "
                f"{unit.value!r}; these units are not convertible"
            )
        return self.value > threshold


class Enforced(StrEnum):
    """Where a control is actually applied."""

    #: The engine enforces it, including for queries that never pass through sql-warden.
    NATIVE = "native"

    #: sql-warden enforces it -- an AST rewrite, an injected clause, a wrapper.
    SERVER = "server"

    #: Not enforced. Present so that a gap is stated rather than implied by omission.
    NONE = "none"


class EnforcementModel(FrozenModel):
    """Where each control is enforced, for this engine.

    Not decoration. The audit entry records this alongside every query, so a reviewer can
    see that masking on Postgres came from an AST rewrite while masking on Snowflake came
    from a policy attached to the column. "A control applied" and "this specific mechanism
    applied" are different claims, and only the second one is evidence.

    It is also what lets the pipeline branch on capability instead of on engine identity:
    the POLICY stage rewrites when masking is SERVER and steps aside when it is NATIVE,
    without ever knowing which database it is talking to.
    """

    readonly: Enforced
    masking: Enforced
    row_limit: Enforced
    timeout: Enforced
