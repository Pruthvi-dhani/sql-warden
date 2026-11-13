import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from sqlglot import exp

from sql_warden.engines import CostEstimate
from sql_warden.models import Decision, Refusal, RefusalCode, TraceEntry
from sql_warden.pipeline.lineage import Lineage


@dataclass
class CheckContext:
    """What the checks share about one query. The SQL is parsed once, by the parse check."""

    sql: str
    dialect: str
    statements: list[exp.Expr] = field(default_factory=list)
    rewrites: list[str] = field(default_factory=list)
    """Checks that change the tree say how here."""
    cost: CostEstimate | None = None
    """The planner's estimate, set by the cost check."""
    lineage: Lineage | None = None
    """Which of the result's columns come from masked columns, set by the masking check."""
    session_id: str | None = None
    """The session the request belongs to; the Warden always sets it."""
    dry_run: bool = False
    """True if the query is only being checked: then nothing may be charged for it."""
    tag: str | None = None
    """Names the request to the database when it plans or runs the query: its audit id."""

    def sql_to_run(self) -> str:
        """The SQL that runs if the query is allowed: the tree as the checks left it,
        regenerated, never the raw text, so nothing the parser read differently from the
        database, or skipped as a comment, gets through."""
        return self.statements[0].sql(dialect=self.dialect, comments=False)


class Check(Protocol):
    name: str

    def run(self, ctx: CheckContext) -> Refusal | None:
        """Return a Refusal to stop the query, or None to let it continue."""
        ...


class Pipeline:
    """Runs checks in order and stops at the first refusal."""

    def __init__(self, checks: Sequence[Check]) -> None:
        self.checks = tuple(checks)

    def run(self, ctx: CheckContext) -> Decision:
        trace: list[TraceEntry] = []
        for check in self.checks:
            started = time.perf_counter()
            try:
                refusal = check.run(ctx)
            except RecursionError:
                # The parse check turns away what it can see is too deep; this is the rest.
                refusal = Refusal(
                    RefusalCode.QUERY_TOO_COMPLEX,
                    "the query nests too deeply to be checked; simplify it",
                )
            except Exception as exc:
                # Fail closed: a check that cannot decide must not wave the query through.
                refusal = Refusal(
                    RefusalCode.INTERNAL_ERROR,
                    f"check {check.name!r} failed unexpectedly: {type(exc).__name__}: {exc}",
                )
            trace.append(TraceEntry(check.name, refusal, (time.perf_counter() - started) * 1000))
            if refusal is not None:
                break
        return Decision(tuple(trace))
