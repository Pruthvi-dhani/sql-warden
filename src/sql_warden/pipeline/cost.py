"""The cost check: the database planner's estimate (EXPLAIN, never run) against a limit.

It comes after the shape and access checks, so only SQL they approved reaches even the
planner, and it explains exactly what would run: the regenerated SQL, with its LIMIT.
"""

from sql_warden.config import CostConfig
from sql_warden.engines import CostEstimate, Engine, EngineError, QueryFailed
from sql_warden.engines.snowflake import BYTES, format_bytes
from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline.base import CheckContext


def format_cost(value: float) -> str:
    """A cost as people read it: 8.44, 500, 14,543, 12,847,522,946."""
    return f"{value:,.2f}" if value < 1000 and value != int(value) else f"{value:,.0f}"


def format_amount(value: float, unit: str | None) -> str:
    """A cost in its unit: bytes as 1.2 GiB, the planner's own units as a plain number."""
    return format_bytes(value) if unit == BYTES else format_cost(value)


_ADVICE = (
    "Filter on indexed columns, join on keys rather than crossing tables, or aggregate over "
    "fewer rows"
)
_ADVICE_BYTES = (
    "Filter on what the table is clustered by (often a date) so fewer partitions are read, "
    "and select only the columns needed"
)


def too_high(estimate: CostEstimate, limit: float, profile: str) -> str:
    """Why a query estimated above limit is refused, and what would bring it under."""
    if estimate.unit == BYTES:
        return (
            f"this query may scan {format_bytes(estimate.total_cost)}, over profile "
            f"{profile}'s limit of {format_bytes(limit)}; most of it is {estimate.top_node}. "
            f"{_ADVICE_BYTES}"
        )
    return (
        f"the planner estimates this query at {format_cost(estimate.total_cost)}, over "
        f"profile {profile}'s limit of {format_cost(limit)}; most of it is "
        f"{estimate.top_node}. {_ADVICE}"
    )


class CostCheck:
    """Refuses queries the planner estimates to cost more than the profile's limit."""

    name = "cost"

    def __init__(self, engine: Engine, limits: CostConfig, *, profile: str) -> None:
        self._engine = engine
        self.limits = limits
        self._profile = profile

    def run(self, ctx: CheckContext) -> Refusal | None:
        try:
            estimate = self._engine.explain(ctx.sql_to_run(), tag=ctx.tag)
        except QueryFailed as exc:
            # Postgres checks some things while planning (types, privileges, constants): the
            # error running the query would have given, before anything ran.
            return Refusal(
                RefusalCode.PLAN_FAILED, f"the database rejected the query while planning it: {exc}"
            )
        except EngineError as exc:
            # Fail closed: a query whose cost is unknown doesn't run.
            return Refusal(
                RefusalCode.COST_UNAVAILABLE, f"could not estimate the query's cost: {exc}"
            )
        ctx.cost = estimate
        limit = self.limits.max_total_cost
        if estimate.total_cost <= limit:
            return None
        return Refusal(RefusalCode.COST_TOO_HIGH, too_high(estimate, limit, self._profile))
