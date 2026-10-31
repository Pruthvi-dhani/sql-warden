from dataclasses import dataclass

from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline import CheckContext
from sql_warden.warden import Warden
from tests.unit.conftest import ONE_ROW, FakeEngine


@dataclass
class RefuseEverything:
    name: str = "refuse-all"

    def run(self, ctx: CheckContext) -> Refusal | None:
        return Refusal(RefusalCode.INTERNAL_ERROR, "test refusal")


def test_parse_always_runs_first() -> None:
    decision = Warden(FakeEngine(), checks=[RefuseEverything()]).check("select 1")
    assert [entry.check for entry in decision.trace] == ["parse", "refuse-all"]


def test_check_never_executes() -> None:
    engine = FakeEngine()
    assert Warden(engine).check("select 1").allowed
    assert engine.executed == []


def test_allowed_query_is_executed() -> None:
    engine = FakeEngine()
    outcome = Warden(engine).run("select 1")
    assert outcome.decision.allowed
    assert outcome.result == ONE_ROW
    assert engine.executed == ["select 1"]


def test_refused_query_never_reaches_the_engine() -> None:
    engine = FakeEngine()
    outcome = Warden(engine, checks=[RefuseEverything()]).run("select 1")
    assert outcome.result is None
    assert not outcome.decision.allowed
    assert engine.executed == []


def test_unparseable_query_never_reaches_the_engine() -> None:
    engine = FakeEngine()
    outcome = Warden(engine).run("select (1")
    assert outcome.result is None
    assert engine.executed == []
