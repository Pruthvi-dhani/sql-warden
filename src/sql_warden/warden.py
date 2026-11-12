import time
from collections.abc import Mapping, Sequence
from dataclasses import replace

from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from sql_warden.audit import AuditError, AuditEvent, AuditSink
from sql_warden.catalog import Catalog
from sql_warden.config import (
    DIALECTS,
    EVERYTHING,
    IMPLICIT_PROFILE,
    BudgetConfig,
    CostConfig,
    MaskRule,
    ShapeConfig,
)
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
    BudgetGate,
    BudgetReservation,
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
from sql_warden.sessions import (
    BudgetStatus,
    MemorySessionStore,
    SessionStore,
    SessionStoreError,
    Usage,
    new_session_id,
)

NOT_COUNTED = frozenset(
    {
        RefusalCode.BUDGET_EXHAUSTED,
        RefusalCode.COST_OVER_BUDGET,
        RefusalCode.BUDGET_UNAVAILABLE,
        RefusalCode.CATALOG_UNAVAILABLE,
        RefusalCode.COST_UNAVAILABLE,
        RefusalCode.AUDIT_UNAVAILABLE,
        RefusalCode.INTERNAL_ERROR,
    }
)
"""Refusals that don't count against a session's max_refusals: the budget's own, and the
ones that are sql-warden's or the database's trouble rather than anything the caller sent."""


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
        budget: BudgetConfig | None = None,
        sessions: SessionStore | None = None,
        default_schema: str | None = None,
    ) -> None:
        if dialect not in DIALECTS:
            raise ValueError(
                f"unknown SQL dialect '{dialect}': the checks read {' and '.join(DIALECTS)}"
            )
        self.engine = engine
        self.audit = audit
        self.dialect = dialect
        """The SQL dialect the checks read queries in: the warehouse's."""
        self.default_schema = default_schema or DEFAULT_SCHEMAS[dialect]
        """Where a table named without a schema is looked up, as the database stores it."""
        self.profile = profile
        """The profile this Warden serves. Fixed for its lifetime."""
        self.session_id = new_session_id()
        """The session of requests that don't name one: this Warden's own, as long as it
        lives. For the CLI and a stdio server that is the process, which serves one caller."""
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
            [
                AccessCheck(
                    self.catalog,
                    access,
                    profile=profile,
                    dialect=dialect,
                    default_schema=self.default_schema,
                )
            ]
            if access is not None
            else []
        )
        # Only for a profile with masked columns: without any, there is nothing to follow.
        masking_checks = (
            [
                MaskingCheck(
                    self.catalog,
                    masks,
                    profile=profile,
                    dialect=dialect,
                    default_schema=self.default_schema,
                )
            ]
            if masks
            else []
        )
        # Last of the built-in checks: the planner sees only SQL the others approved.
        self.cost_check = CostCheck(engine, cost or CostConfig(), profile=profile)
        self.budget = budget or BudgetConfig()
        """What one session may use. Without limits there is no budget check, but usage is
        still counted."""
        if sessions is None:
            # With limits to hold, a session this server hasn't seen starts from what the
            # audit log says it used, so a budget outlives the server that counted it.
            # Without limits there is nothing to hold, and the audit log is left alone.
            restore = self._audited_usage if self.budget.limited else None
            sessions = MemorySessionStore(restore=restore)
        self.sessions: SessionStore = sessions
        # Around the other checks rather than among them: the gate before any of them, the
        # reservation once they have all passed.
        self._gate = Pipeline([BudgetGate(self.sessions, self.budget)])
        self._reservation = Pipeline([BudgetReservation(self.sessions, self.budget)])
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

    def check(
        self, sql: str, *, client: str | None = None, session_id: str | None = None
    ) -> Decision:
        """Run the checks only. Nothing reaches the database. Recorded as a dry run."""
        started = time.perf_counter()
        outcome = QueryOutcome(self._decide(sql, session_id, dry_run=True)[0], result=None)
        return self._recorded(sql, outcome, started, dry_run=True, client=client).decision

    def run(
        self, sql: str, *, client: str | None = None, session_id: str | None = None
    ) -> QueryOutcome:
        """Check the query and, if allowed, execute it. Engine errors are reported in the
        outcome, not raised, so the decision is never lost.

        client names who asked (the MCP client, or cli), for the audit record. session_id is
        the session the request belongs to: without one, this Warden's own."""
        started = time.perf_counter()
        decision, columns = self._decide(sql, session_id)
        if decision.sql is None:
            return self._recorded(sql, QueryOutcome(decision, None), started, client=client)
        try:
            self.audit.ping()
        except Exception as exc:
            # Nothing can be recorded, so nothing runs, and there is no record to write.
            refused = _withheld(decision, f"{_audit_problem(exc)}; the query was not run")
            return QueryOutcome(self._with_budget(refused), result=None)
        try:
            result = self.engine.execute(decision.sql)
            # Known only now, so charged now: the query that takes a session past its rows
            # still comes back, and the next request finds the budget used up.
            if not self._count(self._session(decision), Usage(rows_returned=len(result.rows))):
                raise EngineError(
                    "the rows could not be counted against the session's budget, so they "
                    "are withheld"
                )
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

    def budget_status(self, session_id: str | None = None) -> BudgetStatus:
        """What the session (without one, this Warden's own) has used, against its budget.
        Raises SessionStoreError if its usage can't be read."""
        return BudgetStatus(self.sessions.usage(session_id or self.session_id), self.budget)

    def _audited_usage(self, session_id: str) -> Usage:
        """What the audit log says the session has used under this profile."""
        try:
            return self.audit.usage(session_id, self.profile, not_counted=NOT_COUNTED)
        except Exception as exc:
            # As when recording: an AuditError is written to be shown, a bug is only named.
            raise SessionStoreError(_audit_problem(exc, reading=True)) from exc

    def _decide(
        self, sql: str, session_id: str | None = None, *, dry_run: bool = False
    ) -> tuple[Decision, int | None]:
        """The decision, and how many columns the result will have if any are masked (None
        if none are), to check the rows against before masking them by position.

        Unless it is a dry run, an allowed query is charged to its session here: it is about
        to run. A refusal is charged either way."""
        session_id = session_id or self.session_id
        ctx = CheckContext(sql=sql, dialect=self.dialect, session_id=session_id, dry_run=dry_run)
        decision = replace(self._checked(ctx), profile=self.profile, session_id=session_id)
        if ctx.cost is not None:  # kept on a refusal too: the audit record shows the estimate
            limit = self.cost_check.limits.max_total_cost
            decision = replace(decision, cost=ctx.cost, cost_limit=limit)
        if not decision.allowed:
            refused_by = decision.refused_by
            assert refused_by is not None
            assert refused_by.refusal is not None
            if refused_by.refusal.code not in NOT_COUNTED:
                # Refused either way; if it can't be counted, the gate refuses what follows.
                self._count(session_id, Usage(refusals=1))
            return decision, None
        decision = replace(decision, sql=ctx.sql_to_run(), rewrites=tuple(ctx.rewrites))
        lineage = ctx.lineage
        if lineage is None or not lineage.masked:
            return decision, None
        return replace(decision, masked=self._masked_outputs(lineage)), len(lineage.outputs)

    def _checked(self, ctx: CheckContext) -> Decision:
        """The checks' verdict on ctx, with the budget around them."""
        if self.budget.limited:
            gate = self._gate.run(ctx)
            if not gate.allowed:
                return gate
        decision = self.pipeline.run(ctx)
        if not decision.allowed:
            return decision
        reserved = self._reservation.run(ctx)
        if not self.budget.limited and reserved.allowed:
            return decision  # counted, but with no limits there was nothing to check
        return replace(decision, trace=(*decision.trace, *reserved.trace))

    def _session(self, decision: Decision) -> str:
        return decision.session_id or self.session_id

    def _count(self, session_id: str, spent: Usage) -> bool:
        """Add spent to the session's usage. False if the store failed: callers decide what
        that costs, rather than a request ending without its audit record."""
        try:
            self.sessions.charge(session_id, spent)
        except Exception:
            return False
        return True

    def _with_budget(self, decision: Decision) -> Decision:
        """decision, with what its session has now used of its budget, if it has one."""
        if not self.budget.limited:
            return decision
        try:
            return replace(decision, budget=self.budget_status(self._session(decision)))
        except Exception:
            return decision  # the store is failing, and the decision already says so

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
        outcome = replace(outcome, decision=self._with_budget(outcome.decision))
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
            session_id=decision.session_id,
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
        schema = parsed.db or self.default_schema
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


def _audit_problem(exc: Exception, *, reading: bool = False) -> str:
    # AuditError messages are written to be shown; anything else is a bug, named but not shown.
    if isinstance(exc, AuditError):
        return str(exc)
    what = "read the session's usage from the audit log" if reading else "record the audit event"
    return f"could not {what}: {_crash(exc)}"


def _crash(exc: Exception) -> str:
    return f"unexpected {type(exc).__name__}"


def _withheld(decision: Decision, reason: str, *, duration_ms: float = 0.0) -> Decision:
    """decision, refused by the audit log: the trace keeps what the checks said."""
    entry = TraceEntry("audit", Refusal(RefusalCode.AUDIT_UNAVAILABLE, reason), duration_ms)
    return replace(decision, trace=(*decision.trace, entry), sql=None, rewrites=())
