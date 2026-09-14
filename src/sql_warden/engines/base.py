"""The engine seam.

Everything that differs between databases is declared here and implemented in a sibling
module. The pipeline reads these declarations; it never asks which engine it is talking to.

Design note (plan.md §4.3): a cost estimate is meaningless without its unit. A Postgres
planner cost of 50,000 and 4 GB scanned in Snowflake are not comparable, so there is no
single `max_cost` anywhere in this project -- thresholds are configured per engine, in that
engine's own unit, and validated against what the engine can actually report.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Final, Protocol

from pydantic import Field
from sqlglot import exp

from sql_warden.catalog import Catalog
from sql_warden.models import FrozenModel
from sql_warden.pipeline.decisions import Deny


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


class Guard(Protocol):
    """One engine-specific prohibition, evaluated at the SHAPE stage.

    Guards are where the dangerous-function lists of plan.md §4.4 and §4.5 live --
    `pg_read_file` and `COPY ... TO PROGRAM` on Postgres, `RESULT_SCAN` and `COPY INTO
    <location>` on Snowflake. They are declared by the engine and run by the pipeline,
    which never learns what any of them are checking for.

    Deliberately not inheritable between engines (plan.md decision 10). The lists have
    almost nothing in common, and a guard that looks generic -- "block file access" --
    would quietly under-enforce on whichever engine it was not written for.

    Returning `Deny | None` rather than a bool because a guard knows *why* it refused, and
    that reason has to reach the audit log and the metrics labels intact.
    """

    @property
    def name(self) -> str:
        """Identifies the guard in audit detail. Not a user-facing string."""
        ...

    def check(self, ast: exp.Expression) -> Deny | None:
        """Refuse the query, or raise no objection. Pure: no I/O, no connection."""
        ...


@dataclass(frozen=True, slots=True)
class ResultSet:
    """Rows as they come back from the engine, before the envelope is built.

    Not the §4.7 envelope -- that is assembled in RECORD with the cost, redactions and
    audit id attached, and lands in Stage 7. This is only the part the engine produces.

    Values are `object` rather than `Any`: a database column can hold anything, but nothing
    in this codebase should be able to call an arbitrary method on one without narrowing it
    first.
    """

    columns: tuple[str, ...]
    rows: tuple[tuple[object, ...], ...]


class Session(Protocol):
    """An open, read-only, timeout-bounded transaction against the target.

    Both the COST and EXECUTE stages run through one of these, which is the point. On
    Postgres the read-only mode and the statement timeout are set on the transaction
    (`BEGIN READ ONLY`, `SET LOCAL statement_timeout`), so an estimate taken outside it
    would be an estimate of a query executed under different settings than the one that
    actually runs. Same session, same guarantees, one attempt.
    """

    @property
    def engine_query_id(self) -> str | None:
        """The engine's own identifier for the statement -- Snowflake query id, Postgres
        pid -- recorded in the audit row so the local log can be reconciled against the
        engine's own history (plan.md §4.9). `None` before anything has been issued.
        """
        ...

    async def estimate(self, ast: exp.Query) -> CostEstimate:
        """Cost this query *without running it*, in this engine's own unit."""
        ...

    async def fetch(self, ast: exp.Query) -> ResultSet:
        """Execute and return the rows. Assumes every admission stage already passed."""
        ...


class Engine(Protocol):
    """Everything that differs between databases, declared rather than branched on.

    The pipeline holds one of these and reads its declarations. It never asks which engine
    it is -- cross-cutting rule 2: an `if engine == "snowflake"` anywhere outside this
    package means the capability belongs here instead.

    Two deliberate departures from the illustrative signature in plan.md §4.3:

    The engine owns its connection pool, so no method takes a `conn`. The plan's sketch
    passes one in, which cannot be typed without `Any` (a psycopg `AsyncConnection` and a
    Snowflake connection share no supertype) or without making `Engine` generic, which
    would spread the type parameter through the whole pipeline to no benefit. Stage 2's
    exit criterion is "no `Any` in the protocol", and connection ownership is what buys it.
    It is also the more correct arrangement: see `Session`.

    `estimate` therefore lives on `Session` rather than here, for the same reason.
    """

    @property
    def name(self) -> EngineName:
        """The closed enum, not a free string -- an engine nobody threat-modelled must not
        be summonable by a typo (plan.md decision 10).
        """
        ...

    @property
    def sqlglot_dialect(self) -> str:
        """Dialect used to parse, qualify, and render. `postgres` or `snowflake`."""
        ...

    def guards(self) -> Sequence[Guard]:
        """Engine-specific prohibitions, run at SHAPE."""
        ...

    def enforcement(self) -> EnforcementModel:
        """Where each control is actually applied. Recorded on every audit row, and read
        by POLICY to decide whether to rewrite for masking or step aside for native.
        """
        ...

    def apply_row_limit(self, ast: exp.Query, limit: int) -> exp.Query:
        """Return the query bounded to `limit` rows.

        An AST rewrite, not string concatenation, and the caller asks for one row more than
        it intends to keep -- fetching `n + 1` is how truncation is *known* rather than
        guessed (Stage 7). Engines differ in spelling (`LIMIT`, `FETCH FIRST`, `TOP`),
        which is exactly why this is here and not in the pipeline.

        `exp.Query` rather than `exp.Expression` because that is what SHAPE admits -- a
        `SELECT`, a `UNION`, or a `WITH` whose final expression is one. Taking the narrower
        type means a stage that somehow reached here with a `DELETE` is a type error rather
        than a runtime `AttributeError` on a code path that is meant to be unreachable.
        """
        ...

    async def introspect(self) -> Catalog:
        """Read the live catalog. Called on a cache miss, never per query."""
        ...

    def readonly_session(self, timeout: timedelta) -> AbstractAsyncContextManager[Session]:
        """Open a read-only, timeout-bounded transaction.

        `Enforced.NATIVE` for both engines but by different mechanisms -- a read-only
        transaction on Postgres, RBAC alone on Snowflake, which has no such transaction
        mode. The asymmetry is precisely what `EnforcementModel` exists to record instead
        of hide.
        """
        ...

    async def close(self) -> None:
        """Release the pool. Idempotent."""
        ...
