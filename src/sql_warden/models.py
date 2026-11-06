"""The decision sql-warden reaches about a query, and why."""

from dataclasses import dataclass
from enum import StrEnum

from sql_warden.engines import EngineError, Result


class RefusalCode(StrEnum):
    PARSE_ERROR = "PARSE_ERROR"
    MULTIPLE_STATEMENTS = "MULTIPLE_STATEMENTS"
    NOT_A_SELECT = "NOT_A_SELECT"
    NOT_READ_ONLY = "NOT_READ_ONLY"
    """A SELECT that writes or locks: a data-modifying CTE, SELECT INTO, FOR UPDATE."""
    FUNCTION_NOT_ALLOWED = "FUNCTION_NOT_ALLOWED"
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
class Decision:
    """The outcome of running the checks. Checks after the first refusal do not run."""

    trace: tuple[TraceEntry, ...]
    sql: str | None = None
    """What runs if the query is allowed: regenerated from the checked tree. None if refused."""
    rewrites: tuple[str, ...] = ()
    """How the checks changed the query, e.g. "added LIMIT 101"."""
    profile: str | None = None
    """The profile the query was checked for; the Warden always sets it."""

    @property
    def refused_by(self) -> TraceEntry | None:
        return next((entry for entry in self.trace if not entry.passed), None)

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
