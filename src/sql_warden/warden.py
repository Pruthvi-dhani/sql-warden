import time
from collections.abc import Mapping, Sequence
from dataclasses import replace

from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from sql_warden.audit import AuditError, AuditEvent, AuditSink
from sql_warden.catalog import Catalog
from sql_warden.config import EVERYTHING, IMPLICIT_PROFILE, CostConfig, MaskRule, ShapeConfig
from sql_warden.engines import Engine, EngineError, Result, Table
from sql_warden.models import (
    Decision,
    MaskedOutput,
    QueryOutcome,
    Refusal,
    RefusalCode,
    TraceEntry,
)
from sql_warden.pipeline import (
    AccessCheck,
    Check,
    CheckContext,
    CostCheck,
    MaskingCheck,
    ParseCheck,
    Pipeline,
    ShapeCheck,
)
from sql_warden.pipeline.access import DEFAULT_SCHEMAS
from sql_warden.pipeline.lineage import Lineage, MaskedColumn
from sql_warden.pipeline.masking import Mask, Null, Redact, build_mask
from sql_warden.profiles import Access


class Warden:
    """The single entry point: every query goes through the checks before the engine, and
    every request, allowed or not, is recorded in the audit log before anything is returned.

    Fail-closed: if the audit database is down, an allowed query is not run, and if its record
    can't be written after it ran, its rows are withheld. Either way the caller gets an
    AUDIT_UNAVAILABLE refusal.
    """

    def __init__(
        self,
        engine: Engine,
        *,
        audit: AuditSink,
        dialect: str = "postgres",
        shape: ShapeConfig | None = None,
        checks: Sequence[Check] = (),
        profile: str = IMPLICIT_PROFILE,
        access: Access | None = None,
        cost: CostConfig | None = None,
        masks: Mapping[MaskedColumn, MaskRule] | None = None,
        mask_key: bytes | None = None,
    ) -> None:
        self.engine = engine
        self.audit = audit
        self.dialect = dialect
        self.profile = profile
        """The profile this Warden serves. Fixed for its lifetime."""
        self.access = access
        self.masks: dict[MaskedColumn, MaskRule] = dict(masks or {})
        """The profile's masked columns: (schema, table, column) → its rule."""
        # Built once, so a missing hmac key stops the Warden from starting.
        self._masks: dict[MaskedColumn, Mask] = {
            column: build_mask(rule, key=mask_key) for column, rule in self.masks.items()
        }
        self.catalog = Catalog(engine, dialect=dialect)
        shape_check = ShapeCheck(shape or ShapeConfig(), max_rows=engine.max_rows)
        # The implicit profile has no table rules, so there is nothing for an access check.
        access_checks = (
            [AccessCheck(self.catalog, access, profile=profile, dialect=dialect)]
            if access is not None
            else []
        )
        # Only for a profile with masked columns: without any, there is nothing to follow.
        masking_checks = (
            [MaskingCheck(self.catalog, masks, profile=profile, dialect=dialect)] if masks else []
        )
        # Last of the built-in checks: the planner sees only SQL the others approved.
        self.cost_check = CostCheck(engine, cost or CostConfig(), profile=profile)
        self.pipeline = Pipeline(
            [
                ParseCheck(),
                shape_check,
                *access_checks,
                *masking_checks,
                self.cost_check,
                *checks,
            ]
        )

    def check(self, sql: str, *, client: str | None = None) -> Decision:
        """Run the checks only. Nothing reaches the database. Recorded as a dry run."""
        started = time.perf_counter()
        outcome = QueryOutcome(self._decide(sql)[0], result=None)
        return self._recorded(sql, outcome, started, dry_run=True, client=client).decision

    def run(self, sql: str, *, client: str | None = None) -> QueryOutcome:
        """Check the query and, if allowed, execute it. Engine errors are reported in the
        outcome, not raised, so the decision is never lost.

        client names who asked (the MCP client, or cli), for the audit record."""
        started = time.perf_counter()
        decision, columns = self._decide(sql)
        if decision.sql is None:
            return self._recorded(sql, QueryOutcome(decision, None), started, client=client)
        try:
            self.audit.ping()
        except Exception as exc:
            # Nothing can be recorded, so nothing runs, and there is no record to write.
            refused = _withheld(decision, f"{_audit_problem(exc)}; the query was not run")
            return QueryOutcome(refused, result=None)
        try:
            result = self.engine.execute(decision.sql)
            outcome = QueryOutcome(decision, result=self._masked(result, decision, columns))
        except EngineError as exc:
            outcome = QueryOutcome(decision, result=None, error=exc)
        except Exception as exc:
            # A bug, not a database error: still leave a record of the attempt, then let it
            # surface.
            failed = QueryOutcome(decision, result=None, error=EngineError(_crash(exc)))
            self._recorded(sql, failed, started, client=client)
            raise
        return self._recorded(sql, outcome, started, client=client)

    def _decide(self, sql: str) -> tuple[Decision, int | None]:
        """The decision, and how many columns the result will have if any are masked (None
        if none are), to check the rows against before masking them by position."""
        ctx = CheckContext(sql=sql, dialect=self.dialect)
        decision = replace(self.pipeline.run(ctx), profile=self.profile)
        if ctx.cost is not None:  # kept on a refusal too: the audit record shows the estimate
            limit = self.cost_check.limits.max_total_cost
            decision = replace(decision, cost=ctx.cost, cost_limit=limit)
        if not decision.allowed:
            return decision, None
        decision = replace(decision, sql=ctx.sql_to_run(), rewrites=tuple(ctx.rewrites))
        lineage = ctx.lineage
        if lineage is None or not lineage.masked:
            return decision, None
        return replace(decision, masked=self._masked_outputs(lineage)), len(lineage.outputs)

    def _masked_outputs(self, lineage: Lineage) -> tuple[MaskedOutput, ...]:
        masked = []
        for position, output in enumerate(lineage.outputs):
            flow = output.flow
            if not flow.columns:
                continue
            sources = tuple(sorted(".".join(column) for column in flow.columns))
            if flow.unchanged:
                (column,) = flow.columns
                strategy = self.masks[column].strategy
            else:
                # Computed or mixed: no one column's mask fits, so it is hidden whole. As
                # NULL if a source hides even whether it has a value, else as [REDACTED].
                hide = any(self.masks[column].strategy == "null" for column in flow.columns)
                strategy = "null" if hide else "redact"
            masked.append(
                MaskedOutput(position, output.name, strategy, sources, computed=not flow.unchanged)
            )
        return tuple(masked)

    def _masked(self, result: Result, decision: Decision, columns: int | None) -> Result:
        """result with its masked columns masked."""
        if not decision.masked:
            return result
        if len(result.columns) != columns:
            # Masks go by position: if the columns aren't the ones followed, none of them can
            # be trusted to be in its place, so nothing comes back.
            raise EngineError(
                f"the result has {len(result.columns)} columns where {columns} were expected, "
                "so its masked columns can't be found; nothing is returned"
            )
        masks = {masked.position: self._mask_for(masked) for masked in decision.masked}
        rows = tuple(
            tuple(masks[i].apply(value) if i in masks else value for i, value in enumerate(row))
            for row in result.rows
        )
        return replace(result, rows=rows)

    def _mask_for(self, masked: MaskedOutput) -> Mask:
        if masked.computed:
            return Null() if masked.strategy == "null" else Redact()
        (source,) = masked.sources
        schema, table, column = source.split(".")
        return self._masks[(schema, table, column)]

    def _recorded(
        self,
        sql: str,
        outcome: QueryOutcome,
        started: float,
        *,
        dry_run: bool = False,
        client: str | None,
    ) -> QueryOutcome:
        """The outcome, once its audit record is written; if it can't be, a refusal instead."""
        event = self._event(sql, outcome, started, dry_run=dry_run, client=client)
        writing = time.perf_counter()
        try:
            self.audit.record(event)
        except Exception as exc:
            ran = outcome.result is not None or outcome.error is not None
            consequence = (
                "the query ran, but its results are withheld"
                if ran
                else "nothing is returned without an audit record"
            )
            refused = _withheld(
                outcome.decision,
                f"{_audit_problem(exc)}; {consequence}",
                duration_ms=(time.perf_counter() - writing) * 1000,
            )
            return QueryOutcome(refused, result=None)
        return replace(outcome, decision=replace(outcome.decision, audit_id=event.id))

    def _event(
        self,
        sql: str,
        outcome: QueryOutcome,
        started: float,
        *,
        dry_run: bool,
        client: str | None,
    ) -> AuditEvent:
        decision, result, error = outcome.decision, outcome.result, outcome.error
        refused_by = decision.refused_by
        refusal = refused_by.refusal if refused_by else None
        return AuditEvent(
            profile=self.profile,
            sql=sql,
            decision="refused" if refusal else "failed" if error else "allowed",
            duration_ms=(time.perf_counter() - started) * 1000,
            dry_run=dry_run,
            trace=tuple(trace_step(entry) for entry in decision.trace),
            executed_sql=decision.sql,
            rewrites=decision.rewrites,
            refused_by=refused_by.check if refused_by else None,
            code=refusal.code if refusal else None,
            reason=refusal.reason if refusal else None,
            error=None if error is None else str(error),
            client=client,
            cost_estimate=None if decision.cost is None else decision.cost.total_cost,
            masked_columns=tuple(masked.column for masked in decision.masked),
            rows_returned=None if result is None else len(result.rows),
            truncated=None if result is None else result.truncated,
        )

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


def trace_step(entry: TraceEntry) -> dict[str, object]:
    """One check's verdict as plain data: what the tools return and the audit log stores."""
    refusal = entry.refusal
    return {
        "check": entry.check,
        "passed": refusal is None,
        "code": None if refusal is None else str(refusal.code),
        "reason": None if refusal is None else refusal.reason,
        "duration_ms": round(entry.duration_ms, 3),
    }


def _audit_problem(exc: Exception) -> str:
    # AuditError messages are written to be shown; anything else is a bug, named but not shown.
    if isinstance(exc, AuditError):
        return str(exc)
    return f"could not record the audit event: {_crash(exc)}"


def _crash(exc: Exception) -> str:
    return f"unexpected {type(exc).__name__}"


def _withheld(decision: Decision, reason: str, *, duration_ms: float = 0.0) -> Decision:
    """decision, refused by the audit log: the trace keeps what the checks said."""
    entry = TraceEntry("audit", Refusal(RefusalCode.AUDIT_UNAVAILABLE, reason), duration_ms)
    return replace(decision, trace=(*decision.trace, entry), sql=None, rewrites=())
