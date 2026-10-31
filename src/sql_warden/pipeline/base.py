import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from sqlglot import exp

from sql_warden.models import Decision, Refusal, RefusalCode, TraceEntry


@dataclass
class CheckContext:
    """What the checks share about one query. The SQL is parsed once, by the parse check."""

    sql: str
    dialect: str
    statements: list[exp.Expr] = field(default_factory=list)


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
