"""The decision sql-warden reaches about a query, and why."""

import uuid
from dataclasses import dataclass
from enum import StrEnum

from sql_warden.engines import CostEstimate, EngineError, Result
from sql_warden.sessions import BudgetStatus


class RefusalCode(StrEnum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    """An HTTP request without a token, or with one that isn't valid: unknown, expired,
    signed by someone else, or for another server. Answered 401."""
    NO_PROFILE = "NO_PROFILE"
    """A valid token that gives no profile this server has. Answered 403, never with
    default_profile."""
    AUTH_UNAVAILABLE = "AUTH_UNAVAILABLE"
    """The identity provider's keys could not be fetched, so the token could not be
    checked. Answered 503; worth retrying later."""
    PARSE_ERROR = "PARSE_ERROR"
    QUERY_TOO_COMPLEX = "QUERY_TOO_COMPLEX"
    """Too long, or nested too deeply, to be read safely: reading it could take the checks
    longer than any query is worth."""
    MULTIPLE_STATEMENTS = "MULTIPLE_STATEMENTS"
    NOT_A_SELECT = "NOT_A_SELECT"
    NOT_READ_ONLY = "NOT_READ_ONLY"
    """A SELECT that writes or locks: a data-modifying CTE, SELECT INTO, FOR UPDATE."""
    FUNCTION_NOT_ALLOWED = "FUNCTION_NOT_ALLOWED"
    TYPE_NOT_ALLOWED = "TYPE_NOT_ALLOWED"
    """A cast to a type that isn't standard SQL: a table's row type, or one that looks a
    name up in the database's catalog. Either tells what the profile can't see is there."""
    TOO_MANY_JOINS = "TOO_MANY_JOINS"
    SUBQUERY_TOO_DEEP = "SUBQUERY_TOO_DEEP"
    LIMIT_REQUIRED = "LIMIT_REQUIRED"
    LIMIT_TOO_HIGH = "LIMIT_TOO_HIGH"
    INVALID_LIMIT = "INVALID_LIMIT"
    TABLE_NOT_ALLOWED = "TABLE_NOT_ALLOWED"
    """A table the profile may not read, or one that doesn't exist: the two look the same."""
    COLUMN_NOT_ALLOWED = "COLUMN_NOT_ALLOWED"
    STAR_NOT_ALLOWED = "STAR_NOT_ALLOWED"
    """* (or a whole-row reference) on a table the profile may read only some columns of."""
    CATALOG_UNAVAILABLE = "CATALOG_UNAVAILABLE"
    """The tables and columns could not be read, so access could not be checked."""
    MASKED_COLUMN_IN_PREDICATE = "MASKED_COLUMN_IN_PREDICATE"
    """A masked column used to filter, join, group, sort or compare rows: what comes back
    would depend on the values the mask hides."""
    MASKED_COLUMN_IN_EXPRESSION = "MASKED_COLUMN_IN_EXPRESSION"
    """A masked column inside an expression, or one that can't be followed to the output: it
    can only be selected as it is, or counted."""
    COST_TOO_HIGH = "COST_TOO_HIGH"
    """The planner estimates the query costs more than the profile's max_total_cost."""
    COST_UNAVAILABLE = "COST_UNAVAILABLE"
    """The database couldn't be reached, or took too long to plan the query, so its cost is
    unknown. Worth retrying later."""
    PLAN_FAILED = "PLAN_FAILED"
    """The database rejected the query while planning it: a type error, a table its role
    can't read, a constant like 1/0. Its error says why; retrying won't help."""
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    """The session has used up its budget: its queries, their total cost, the rows returned
    or its refusals reached the profile's limit. Nothing more runs in this session."""
    COST_OVER_BUDGET = "COST_OVER_BUDGET"
    """The planner estimates the query costs more than the session has left to spend. A
    cheaper query may still fit."""
    BUDGET_UNAVAILABLE = "BUDGET_UNAVAILABLE"
    """What the session has used could not be read, so its budget could not be checked.
    Worth retrying later."""
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    """The request could not be recorded, so nothing it would return is returned."""
    INTERNAL_ERROR = "INTERNAL_ERROR"
    """A check crashed. The query is refused rather than let through unchecked."""


@dataclass(frozen=True)
class Refusal:
    code: RefusalCode
    reason: str


@dataclass(frozen=True)
class TraceEntry:
    check: str
    refusal: Refusal | None
    duration_ms: float

    @property
    def passed(self) -> bool:
        return self.refusal is None


@dataclass(frozen=True)
class MaskedOutput:
    """A column of the result that comes back masked."""

    position: int
    """Where it is in the result, from 0."""
    column: str
    strategy: str
    """redact, partial, hmac or null."""
    sources: tuple[str, ...]
    """The masked columns it comes from, as schema.table.column."""
    computed: bool = False
    """True if it was computed or mixed from them rather than selected as it is: then it is
    hidden entirely, whatever their own masks."""


@dataclass(frozen=True)
class Decision:
    """The outcome of running the checks. Checks after the first refusal do not run."""

    trace: tuple[TraceEntry, ...]
    sql: str | None = None
    """What runs if the query is allowed: regenerated from the checked tree. None if refused."""
    rewrites: tuple[str, ...] = ()
    """How the checks changed the query, e.g. "added LIMIT 101"."""
    profile: str | None = None
    """The profile the query was checked for; the Warden always sets it."""
    session_id: str | None = None
    """The session the request belongs to; the Warden always sets it."""
    cost: CostEstimate | None = None
    """The planner's estimate, once the cost check got one, whether or not it refused."""
    cost_limit: float | None = None
    """The profile's max_total_cost, when there is an estimate to hold against it."""
    masked: tuple[MaskedOutput, ...] = ()
    """The result's columns that are masked, or would be for a dry run."""
    budget: BudgetStatus | None = None
    """What the session has used of its budget, this request included. None for a profile
    without limits."""
    audit_id: uuid.UUID | None = None
    """The audit record of this request; None only when it could not be written."""

    @property
    def refused_by(self) -> TraceEntry | None:
        # The checks stop at the first refusal, so they refuse at most once. An audit failure
        # comes after them, and is why nothing was returned, even for a query already refused.
        return next((entry for entry in reversed(self.trace) if not entry.passed), None)

    @property
    def allowed(self) -> bool:
        return self.refused_by is None


@dataclass(frozen=True)
class QueryOutcome:
    decision: Decision
    result: Result | None
    """None when the query was refused or failed."""
    error: EngineError | None = None
    """Why an allowed query did not produce a result."""
