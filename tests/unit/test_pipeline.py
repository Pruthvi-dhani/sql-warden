from dataclasses import dataclass, field

import pytest

from sql_warden.models import Decision, Refusal, RefusalCode, TraceEntry
from sql_warden.pipeline import CheckContext, Pipeline

REFUSAL = Refusal(RefusalCode.PARSE_ERROR, "nope")


@dataclass
class FakeCheck:
    name: str
    refusal: Refusal | None = None
    error: Exception | None = None
    calls: list[str] = field(default_factory=list)

    def run(self, ctx: CheckContext) -> Refusal | None:
        self.calls.append(ctx.sql)
        if self.error is not None:
            raise self.error
        return self.refusal


def _ctx() -> CheckContext:
    return CheckContext(sql="select 1", dialect="postgres")


def test_all_checks_pass_in_order() -> None:
    a, b, c = FakeCheck("a"), FakeCheck("b"), FakeCheck("c")
    decision = Pipeline([a, b, c]).run(_ctx())
    assert decision.allowed
    assert decision.refused_by is None
    assert [entry.check for entry in decision.trace] == ["a", "b", "c"]
    assert all(entry.passed and entry.duration_ms >= 0 for entry in decision.trace)


def test_first_refusal_stops_the_pipeline() -> None:
    a, b, c = FakeCheck("a"), FakeCheck("b", refusal=REFUSAL), FakeCheck("c")
    decision = Pipeline([a, b, c]).run(_ctx())
    assert not decision.allowed
    assert decision.refused_by == decision.trace[-1]
    assert [(entry.check, entry.refusal) for entry in decision.trace] == [
        ("a", None),
        ("b", REFUSAL),
    ]
    assert c.calls == []


@pytest.mark.parametrize("error", [RuntimeError("boom"), KeyError("missing")])
def test_a_crashing_check_refuses_instead_of_passing(error: Exception) -> None:
    after = FakeCheck("after")
    decision = Pipeline([FakeCheck("broken", error=error), after]).run(_ctx())
    refusal = decision.trace[0].refusal
    assert refusal is not None
    assert refusal.code is RefusalCode.INTERNAL_ERROR
    assert "'broken'" in refusal.reason
    assert type(error).__name__ in refusal.reason
    assert after.calls == []


def test_checks_share_one_context() -> None:
    seen: list[str] = []

    @dataclass
    class Writer:
        name: str = "writer"

        def run(self, ctx: CheckContext) -> Refusal | None:
            ctx.sql = ctx.sql.upper()
            return None

    @dataclass
    class Reader:
        name: str = "reader"

        def run(self, ctx: CheckContext) -> Refusal | None:
            seen.append(ctx.sql)
            return None

    Pipeline([Writer(), Reader()]).run(_ctx())
    assert seen == ["SELECT 1"]


def test_decision_with_refusal_in_the_middle_reports_it() -> None:
    entries = (
        TraceEntry("a", None, 0.1),
        TraceEntry("b", REFUSAL, 0.1),
    )
    decision = Decision(entries)
    assert decision.refused_by is entries[1]
    assert not decision.allowed
