"""The budget check: what a session has used, against what its profile lets a session use.

It has two parts, both called `budget` in the trace. The gate comes before every other
check: a session that has reached a limit gets nothing more, not even the other checks'
reasons to learn from. The reservation comes after them all, once the query's cost is known:
it counts the query and its estimated cost against the budget in one step, so requests
arriving at once can't spend the same last query. Rows and refusals are only known
afterwards, and the Warden charges them then.
"""

from sql_warden.config import BudgetConfig
from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline.base import CheckContext
from sql_warden.pipeline.cost import format_cost
from sql_warden.sessions import SessionStore, Usage, over, reached


def _session(ctx: CheckContext) -> str:
    if ctx.session_id is None:
        raise ValueError("the request has no session to hold a budget against")
    return ctx.session_id


def used_up(limit: str, usage: Usage, budget: BudgetConfig) -> Refusal:
    """The refusal for a session that has reached limit."""
    most = getattr(budget, limit)
    what = {
        "max_queries": f"it has run {usage.queries:,} of its {most:,} queries",
        "max_total_cost": f"its queries have cost {format_cost(usage.total_cost)} of the "
        f"{format_cost(most)} it may spend",
        "max_rows_returned": f"it has been returned {usage.rows_returned:,} rows, and its "
        f"limit is {most:,}",
        "max_refusals": f"{usage.refusals:,} of its requests were refused, and its limit is "
        f"{most:,}",
    }[limit]
    return Refusal(
        RefusalCode.BUDGET_EXHAUSTED,
        f"this session's budget is used up: {what}. Nothing more runs in this session",
    )


class BudgetGate:
    """Refuses everything from a session that has reached one of its limits."""

    name = "budget"

    def __init__(self, sessions: SessionStore, budget: BudgetConfig) -> None:
        self._sessions = sessions
        self._budget = budget

    def run(self, ctx: CheckContext) -> Refusal | None:
        usage = self._sessions.usage(_session(ctx))
        limit = reached(usage, self._budget)
        return None if limit is None else used_up(limit, usage, self._budget)


class BudgetReservation:
    """Counts an approved query and its estimated cost against the session's budget, and
    refuses it if they don't fit. A dry run is told whether they would, and charged nothing."""

    name = "budget"

    def __init__(self, sessions: SessionStore, budget: BudgetConfig) -> None:
        self._sessions = sessions
        self._budget = budget

    def run(self, ctx: CheckContext) -> Refusal | None:
        session_id = _session(ctx)
        spent = Usage(queries=1, total_cost=0.0 if ctx.cost is None else ctx.cost.total_cost)
        if ctx.dry_run:
            used = self._sessions.usage(session_id)
            exceeded = over(used + spent, self._budget)
        else:
            charge = self._sessions.charge(session_id, spent, within=self._budget)
            used, exceeded = charge.usage, charge.exceeded
        if exceeded is None:
            return None
        most = self._budget.max_total_cost
        if exceeded == "max_total_cost" and most is not None and used.total_cost < most:
            return Refusal(
                RefusalCode.COST_OVER_BUDGET,
                f"the planner estimates this query at {format_cost(spent.total_cost)}, more "
                f"than the {format_cost(most - used.total_cost)} this session has left of the "
                f"{format_cost(most)} it may spend. A cheaper query may still fit",
            )
        return used_up(exceeded, used, self._budget)
