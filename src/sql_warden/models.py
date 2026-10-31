"""The decision sql-warden reaches about a query, and why."""

from dataclasses import dataclass
from enum import StrEnum

from sql_warden.engines import Result


class RefusalCode(StrEnum):
    PARSE_ERROR = "PARSE_ERROR"
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
    """None when the query was refused."""
