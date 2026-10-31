from collections.abc import Sequence

from sql_warden.engines import Engine
from sql_warden.models import Decision, QueryOutcome
from sql_warden.pipeline import Check, CheckContext, ParseCheck, Pipeline


class Warden:
    """The single entry point: every query goes through the checks before the engine."""

    def __init__(
        self, engine: Engine, *, dialect: str = "postgres", checks: Sequence[Check] = ()
    ) -> None:
        self.engine = engine
        self.dialect = dialect
        self.pipeline = Pipeline([ParseCheck(), *checks])

    def check(self, sql: str) -> Decision:
        """Run the checks only. Nothing reaches the database."""
        return self.pipeline.run(CheckContext(sql=sql, dialect=self.dialect))

    def run(self, sql: str) -> QueryOutcome:
        decision = self.check(sql)
        if not decision.allowed:
            return QueryOutcome(decision, result=None)
        return QueryOutcome(decision, result=self.engine.execute(sql))
