"""The cost check: the database planner's estimate (EXPLAIN, never run) against a limit.

It comes after the shape and access checks, so only SQL they approved reaches even the
planner, and it explains exactly what would run: the regenerated SQL, with its LIMIT.
"""

from sql_warden.config import CostConfig
from sql_warden.engines import Engine, EngineError, QueryFailed
from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline.base import CheckContext


def format_cost(value: float) -> str:
    """A cost as people read it: 8.44, 500, 14,543, 12,847,522,946."""
    return f"{value:,.2f}" if value < 1000 and value != int(value) else f"{value:,.0f}"


class CostCheck:
    """Refuses queries the planner estimates to cost more than the profile's limit."""

    name = "cost"

    def __init__(self, engine: Engine, limits: CostConfig, *, profile: str) -> None:
        self._engine = engine
        self.limits = limits
        self._profile = profile

    def run(self, ctx: CheckContext) -> Refusal | None:
        try:
            estimate = self._engine.explain(ctx.sql_to_run())
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
        return Refusal(
            RefusalCode.COST_TOO_HIGH,
            f"the planner estimates this query at {format_cost(estimate.total_cost)}, over "
            f"profile {self._profile}'s limit of {format_cost(limit)}; most of it is "
            f"{estimate.top_node}. Filter on indexed columns, join on keys rather than "
            "crossing tables, or aggregate over fewer rows",
        )
