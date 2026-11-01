from dataclasses import dataclass

from sql_warden.config import ShapeConfig
from sql_warden.engines import QueryTimeout
from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline import CheckContext
from sql_warden.warden import Warden
from tests.unit.conftest import ONE_ROW, PRODUCTS, FakeEngine


@dataclass
class RefuseEverything:
    name: str = "refuse-all"

    def run(self, ctx: CheckContext) -> Refusal | None:
        return Refusal(RefusalCode.INTERNAL_ERROR, "test refusal")


def test_parse_and_shape_always_run_first() -> None:
    decision = Warden(FakeEngine(), checks=[RefuseEverything()]).check("select 1")
    assert [entry.check for entry in decision.trace] == ["parse", "shape", "refuse-all"]


def test_check_never_executes() -> None:
    engine = FakeEngine()
    assert Warden(engine).check("select 1").allowed
    assert engine.executed == []


def test_allowed_query_is_executed() -> None:
    engine = FakeEngine()
    outcome = Warden(engine).run("select 1 limit 1")
    assert outcome.decision.allowed
    assert outcome.result == ONE_ROW
    assert engine.executed == ["SELECT 1 LIMIT 1"]


def test_what_runs_is_the_checked_tree_not_the_raw_text() -> None:
    # Comments are dropped: nothing the parser skipped over can reach the database.
    engine = FakeEngine()
    decision = Warden(engine).check("select id /* hi */ from t -- */ ; drop table t\nlimit 5")
    assert decision.sql == "SELECT id FROM t LIMIT 5"
    assert decision.rewrites == ()


def test_rewrites_are_reported_and_executed() -> None:
    engine = FakeEngine(max_rows=10)
    outcome = Warden(engine).run("select id from t")
    assert outcome.decision.rewrites == ("added LIMIT 11 (row cap 10 + 1 to detect truncation)",)
    assert engine.executed == ["SELECT id FROM t LIMIT 11"]


def test_shape_rules_are_passed_to_the_shape_check() -> None:
    decision = Warden(FakeEngine(), shape=ShapeConfig(limit="require")).check("select 1")
    refused_by = decision.refused_by
    assert refused_by is not None
    assert refused_by.refusal is not None
    assert refused_by.refusal.code is RefusalCode.LIMIT_REQUIRED


def test_refused_decisions_carry_no_sql() -> None:
    decision = Warden(FakeEngine()).check("delete from t")
    assert decision.sql is None


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


def test_engine_errors_are_reported_with_the_decision() -> None:
    error = QueryTimeout("query cancelled")
    outcome = Warden(FakeEngine(error=error)).run("select 1")
    assert outcome.error is error
    assert outcome.result is None
    assert outcome.decision.allowed
    assert outcome.decision.sql == "SELECT 1 LIMIT 101"


def test_tables_come_from_the_engine() -> None:
    assert Warden(FakeEngine()).tables() == (PRODUCTS,)
