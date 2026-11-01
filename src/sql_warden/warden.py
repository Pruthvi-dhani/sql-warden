from collections.abc import Sequence
from dataclasses import replace

from sql_warden.config import ShapeConfig
from sql_warden.engines import Engine
from sql_warden.models import Decision, QueryOutcome
from sql_warden.pipeline import Check, CheckContext, ParseCheck, Pipeline, ShapeCheck


class Warden:
    """The single entry point: every query goes through the checks before the engine."""

    def __init__(
        self,
        engine: Engine,
        *,
        dialect: str = "postgres",
        shape: ShapeConfig | None = None,
        checks: Sequence[Check] = (),
    ) -> None:
        self.engine = engine
        self.dialect = dialect
        shape_check = ShapeCheck(shape or ShapeConfig(), max_rows=engine.max_rows)
        self.pipeline = Pipeline([ParseCheck(), shape_check, *checks])

    def check(self, sql: str) -> Decision:
        """Run the checks only. Nothing reaches the database."""
        ctx = CheckContext(sql=sql, dialect=self.dialect)
        decision = self.pipeline.run(ctx)
        if not decision.allowed:
            return decision
        # What runs is the tree the checks approved, regenerated, never the raw text: nothing
        # the parser read differently from the database, or skipped as a comment, gets through.
        final_sql = ctx.statements[0].sql(dialect=self.dialect, comments=False)
        return replace(decision, sql=final_sql, rewrites=tuple(ctx.rewrites))

    def run(self, sql: str) -> QueryOutcome:
        decision = self.check(sql)
        if decision.sql is None:
            return QueryOutcome(decision, result=None)
        return QueryOutcome(decision, result=self.engine.execute(decision.sql))
