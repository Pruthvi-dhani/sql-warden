"""The budget check: what a session has used, against what its profile lets a session use;
and, for a caller with a token, what they have used over the window across all their
sessions, against what the profile lets a caller use. Both are held to: whichever runs out
first refuses, and the refusal says which.

It has two parts, both called `budget` in the trace. The gate comes before every other
check: a session that has reached a limit gets nothing more, not even the other checks'
reasons to learn from. The reservation comes after them all, once the query's cost is known:
it counts the query and its estimated cost against the budget in one step, so requests
arriving at once can't spend the same last query. Rows and refusals are only known
afterwards, and the Warden charges them then.
"""

from sql_warden.config import BudgetConfig, IdentityBudgetConfig
from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline.base import CheckContext
from sql_warden.pipeline.cost import format_cost
from sql_warden.sessions import (
    CallerCharge,
    SessionStore,
    SessionStoreError,
    Usage,
    over,
    reached,
)


def _session(ctx: CheckContext) -> str:
    if ctx.session_id is None:
        raise ValueError("the request has no session to hold a budget against")
    return ctx.session_id


def unavailable(exc: SessionStoreError) -> Refusal:
    """Fail closed: a query whose session's usage is unknown doesn't run."""
    return Refusal(
        RefusalCode.BUDGET_UNAVAILABLE, f"this session's budget could not be checked: {exc}"
    )


def window(hours: float) -> str:
    """A window as a refusal names it: "24 hours", "90 minutes", "7 days"."""
    if hours >= 48 and hours % 24 == 0:
        return f"{hours // 24:.0f} days"
    if hours < 1:
        return f"{hours * 60:.0f} minutes"
    return f"{hours:g} hour{'' if hours == 1 else 's'}"


def caller_used_up(limit: str, usage: Usage, budget: IdentityBudgetConfig, caller: str) -> Refusal:
    """The refusal for a caller who has reached limit over the window."""
    most = getattr(budget, limit)
    span = window(budget.window_hours)
    what = {
        "max_queries": f"they have run {usage.queries:,} of their {most:,} queries",
        "max_total_cost": f"their queries have cost {format_cost(usage.total_cost)} of the "
        f"{format_cost(most)} they may spend",
        "max_rows_returned": f"they have been returned {usage.rows_returned:,} rows, and "
        f"their limit is {most:,}",
        "max_refusals": f"{usage.refusals:,} of their requests were refused, and their limit "
        f"is {most:,}",
    }[limit]
    return Refusal(
        RefusalCode.BUDGET_EXHAUSTED,
        f"{caller}'s budget for any {span} is used up: {what} in the last {span}, over all "
        "their sessions. Nothing more runs for them until earlier use is older than that",
    )


def _caller(ctx: CheckContext, budget: IdentityBudgetConfig) -> CallerCharge | None:
    """The caller to charge as well as the session, if they have a budget to hold."""
    if ctx.identity is None or not budget.limited:
        return None
    return CallerCharge(ctx.identity, budget.window_s, within=budget)


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
    """Refuses everything from a session, or a caller, that has reached one of its limits."""

    name = "budget"

    def __init__(
        self,
        sessions: SessionStore,
        budget: BudgetConfig,
        identity_budget: IdentityBudgetConfig | None = None,
    ) -> None:
        self._sessions = sessions
        self._budget = budget
        self._identity_budget = identity_budget or IdentityBudgetConfig()

    def run(self, ctx: CheckContext) -> Refusal | None:
        caller = _caller(ctx, self._identity_budget)
        try:
            usage = self._sessions.usage(_session(ctx))
            limit = reached(usage, self._budget)
            if limit is not None:
                return used_up(limit, usage, self._budget)
            if caller is None:
                return None
            theirs = self._sessions.caller_usage(caller.name, caller.window_s)
        except SessionStoreError as exc:
            return unavailable(exc)
        limit = reached(theirs, self._identity_budget)
        if limit is None:
            return None
        return caller_used_up(limit, theirs, self._identity_budget, caller.name)


class BudgetReservation:
    """Counts an approved query and its estimated cost against the session's budget, and
    refuses it if they don't fit. A dry run is told whether they would, and charged nothing."""

    name = "budget"

    def __init__(
        self,
        sessions: SessionStore,
        budget: BudgetConfig,
        identity_budget: IdentityBudgetConfig | None = None,
    ) -> None:
        self._sessions = sessions
        self._budget = budget
        self._identity_budget = identity_budget or IdentityBudgetConfig()

    def run(self, ctx: CheckContext) -> Refusal | None:
        session_id = _session(ctx)
        caller = _caller(ctx, self._identity_budget)
        spent = Usage(queries=1, total_cost=0.0 if ctx.cost is None else ctx.cost.total_cost)
        by = "session"
        try:
            if ctx.dry_run:
                used = self._sessions.usage(session_id)
                exceeded = over(used + spent, self._budget)
                if exceeded is None and caller is not None:
                    used = self._sessions.caller_usage(caller.name, caller.window_s)
                    exceeded, by = over(used + spent, self._identity_budget), "caller"
            else:
                charge = self._sessions.charge(
                    session_id, spent, within=self._budget, caller=caller
                )
                exceeded, by = charge.exceeded, charge.by or "session"
                used = charge.usage
                if by == "caller" and charge.caller_usage is not None:
                    used = charge.caller_usage
        except SessionStoreError as exc:
            return unavailable(exc)
        if exceeded is None:
            return None
        if by == "caller" and caller is not None:
            return self._refused(exceeded, spent, used, self._identity_budget, caller.name)
        return self._refused(exceeded, spent, used, self._budget, None)

    def _refused(
        self,
        exceeded: str,
        spent: Usage,
        used: Usage,
        budget: BudgetConfig,
        caller: str | None,
    ) -> Refusal:
        most = budget.max_total_cost
        if exceeded == "max_total_cost" and most is not None and used.total_cost < most:
            if caller is None:
                whose = "this session has left"
                spends = "it may spend"
            else:
                assert isinstance(budget, IdentityBudgetConfig)
                whose = f"{caller} has left"
                spends = f"they may spend in any {window(budget.window_hours)}"
            return Refusal(
                RefusalCode.COST_OVER_BUDGET,
                f"the planner estimates this query at {format_cost(spent.total_cost)}, more "
                f"than the {format_cost(most - used.total_cost)} {whose} of the "
                f"{format_cost(most)} {spends}. A cheaper query may still fit",
            )
        if caller is None:
            return used_up(exceeded, used, budget)
        assert isinstance(budget, IdentityBudgetConfig)
        return caller_used_up(exceeded, used, budget, caller)
