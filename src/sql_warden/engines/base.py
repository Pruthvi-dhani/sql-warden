"""The engine seam.

Stage 1 lands only the vocabulary that `config.py` needs to validate itself: which engines
exist, and what units they can express a cost estimate in. The `Engine` protocol itself,
along with `CostEstimate`, `EnforcementModel`, `Guard` and `Session`, arrives in Stage 2.

Design note (plan.md §4.3): a cost estimate is meaningless without its unit. A Postgres
planner cost of 50,000 and 4 GB scanned in Snowflake are not comparable, so there is no
single `max_cost` anywhere in this project -- thresholds are configured per engine, in that
engine's own unit, and validated against what the engine can actually report.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Final


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
