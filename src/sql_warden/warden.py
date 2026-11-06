from collections.abc import Sequence
from dataclasses import replace

from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from sql_warden.catalog import Catalog
from sql_warden.config import EVERYTHING, IMPLICIT_PROFILE, ShapeConfig
from sql_warden.engines import Engine, EngineError, Table
from sql_warden.models import Decision, QueryOutcome
from sql_warden.pipeline import AccessCheck, Check, CheckContext, ParseCheck, Pipeline, ShapeCheck
from sql_warden.pipeline.access import DEFAULT_SCHEMAS
from sql_warden.profiles import Access


class Warden:
    """The single entry point: every query goes through the checks before the engine."""

    def __init__(
        self,
        engine: Engine,
        *,
        dialect: str = "postgres",
        shape: ShapeConfig | None = None,
        checks: Sequence[Check] = (),
        profile: str = IMPLICIT_PROFILE,
        access: Access | None = None,
    ) -> None:
        self.engine = engine
        self.dialect = dialect
        self.profile = profile
        """The profile this Warden serves. Fixed for its lifetime."""
        self.access = access
        self.catalog = Catalog(engine, dialect=dialect)
        shape_check = ShapeCheck(shape or ShapeConfig(), max_rows=engine.max_rows)
        # The implicit profile has no table rules, so there is nothing for an access check.
        access_checks = (
            [AccessCheck(self.catalog, access, profile=profile, dialect=dialect)]
            if access is not None
            else []
        )
        self.pipeline = Pipeline([ParseCheck(), shape_check, *access_checks, *checks])

    def check(self, sql: str) -> Decision:
        """Run the checks only. Nothing reaches the database."""
        ctx = CheckContext(sql=sql, dialect=self.dialect)
        decision = replace(self.pipeline.run(ctx), profile=self.profile)
        if not decision.allowed:
            return decision
        # What runs is the tree the checks approved, regenerated, never the raw text: nothing
        # the parser read differently from the database, or skipped as a comment, gets through.
        final_sql = ctx.statements[0].sql(dialect=self.dialect, comments=False)
        return replace(decision, sql=final_sql, rewrites=tuple(ctx.rewrites))

    def run(self, sql: str) -> QueryOutcome:
        """Check the query and, if allowed, execute it. Engine errors are reported in the
        outcome, not raised, so the decision is never lost."""
        decision = self.check(sql)
        if decision.sql is None:
            return QueryOutcome(decision, result=None)
        try:
            return QueryOutcome(decision, result=self.engine.execute(decision.sql))
        except EngineError as exc:
            return QueryOutcome(decision, result=None, error=exc)

    def tables(self) -> tuple[Table, ...]:
        """The tables and columns this profile may read, in catalog order. Anything else is
        left out entirely, so a profile never learns that it exists."""
        visible = []
        for table in self.catalog.tables():
            allowed = self._allowed(table)
            if allowed == EVERYTHING:
                visible.append(table)
            elif allowed:
                columns = tuple(column for column in table.columns if column.name in allowed)
                visible.append(replace(table, columns=columns))
        return tuple(visible)

    def table(self, name: str) -> Table | None:
        """The table name refers to, read as SQL would (`products` is public.products,
        `"MixedCase"` keeps its case), if this profile may read it."""
        try:
            parsed = exp.to_table(name, dialect=self.dialect)
        except SqlglotError:
            return None
        if parsed.catalog:
            return None
        normalize_identifiers(parsed, dialect=self.dialect)
        schema = parsed.db or DEFAULT_SCHEMAS[self.dialect]
        return next((t for t in self.tables() if (t.schema, t.name) == (schema, parsed.name)), None)

    def all_columns(self, table: Table) -> bool:
        """True if this profile may read every column of table, including ones added later,
        so SELECT * on it is allowed."""
        return self._allowed(table) == EVERYTHING

    def _allowed(self, table: Table) -> frozenset[str] | str | None:
        if self.access is None:
            return EVERYTHING
        return self.access.columns(table.schema, table.name)
