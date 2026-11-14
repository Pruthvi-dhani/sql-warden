"""The MCP server: how agents reach the warden.

Over stdio for an agent that launches sql-warden itself, or over HTTP on the loopback
interface for local tools such as the test portal. The HTTP transport has no authentication
yet, so it never listens anywhere else.
"""

import datetime
import hashlib
import uuid
from decimal import Decimal
from typing import Annotated, Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.streamable_http import MCP_SESSION_ID_HEADER
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field
from starlette.applications import Starlette

from sql_warden import __version__
from sql_warden.config import IMPLICIT_PROFILE, LOOPBACK_ONLY, is_loopback
from sql_warden.engines import EngineError, Table
from sql_warden.models import Decision, QueryOutcome
from sql_warden.sessions import MAX_SESSIONS, BudgetStatus, SessionStoreError
from sql_warden.warden import Warden, trace_step

INSTRUCTIONS = """\
sql-warden runs read-only SQL against a governed database. Every query goes through checks
before it runs; a refused query comes back with the check, a code and a reason, so you can
fix it and try again. Only single SELECT statements are allowed. Results are capped: if a
query has no LIMIT, or one above the cap, sql-warden adds or lowers it and says so in
`rewrites`; `truncated` tells you whether rows were cut off. A query the database's planner
estimates as too expensive is refused (COST_TOO_HIGH), with the costliest step named:
filter on indexed columns or aggregate less. Some columns are masked (list_tables marks
them): they come back hidden, as `masked_columns` says, and can only be selected as they are
or counted; filtering, joining, grouping, sorting or computing with them is refused. Use
list_tables to see what you
can query, describe_table for one table's columns, and check_query to test a query without
running it. Tables and columns that aren't listed can't be queried. SELECT * works only on
tables with `all_columns: true`; elsewhere, name the columns. A session may have a budget:
how many queries it may run, what they may cost in total, how many rows it may be returned,
and how many of its requests may be refused (dry runs included). budget_status shows what
is used and what is left, as does `budget` in each result. COST_OVER_BUDGET means this query
costs more than is left, and a cheaper one may fit; BUDGET_EXHAUSTED means the session is
done, and nothing more will run in it."""

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)
MAX_REQUEST_BYTES = 256 * 1024
"""The largest HTTP request body read. A request carries one query of at most 20,000
characters; the rest is the envelope around it."""
SESSION_IDLE_S = 30 * 60.0
"""How long a connection may send nothing before the server closes its session. The client
connects again and gets a new one, with a new budget."""


class TraceStep(BaseModel):
    check: str
    passed: bool
    code: str | None = None
    reason: str | None = None
    duration_ms: float


class CostInfo(BaseModel):
    total_cost: float
    """The planner's estimate for the whole query, in its own units."""
    max_total_cost: float
    """The profile's limit: a query estimated above it is refused with COST_TOO_HIGH."""
    est_rows: int | None = None
    """The rows the planner expects the query to return. Missing where it doesn't say
    (Snowflake)."""
    top_node: str
    """The step of the plan that adds the most cost, e.g. "Seq Scan on orders"."""
    unit: str | None = None
    """What total_cost counts, where it has a name: "bytes" (that the query may scan) for
    Snowflake. Missing for Postgres, whose units are only the planner's."""


class QueryRows(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    row_count: int
    truncated: bool
    """True when the query produced more rows than the row cap; only the first ones are here."""
    duration_ms: float


class MaskedColumnInfo(BaseModel):
    column: str
    """The result's column, by name."""
    position: int
    """And by position, from 0: names can repeat."""
    strategy: str
    """How it is masked: redact, partial, hmac or null."""
    sources: list[str]
    """The masked columns it comes from, as schema.table.column."""


class BudgetLine(BaseModel):
    used: float
    limit: float | None = None
    """The most the session may use. Missing where the profile sets no limit."""
    remaining: float | None = None
    """What is left under the limit: 0 once it is reached."""


class BudgetInfo(BaseModel):
    queries: BudgetLine
    """Queries that were allowed and sent to the database. Dry runs aren't counted."""
    total_cost: BudgetLine
    """The sum of their estimated costs, in the planner's units."""
    rows_returned: BudgetLine
    refusals: BudgetLine
    """Requests a check refused, dry runs included."""
    exhausted: str | None = None
    """The limit the session has reached, e.g. max_queries. Then nothing more runs in it."""


class BudgetResponse(BaseModel):
    profile: str
    session_id: str
    budget: BudgetInfo


class QueryResponse(BaseModel):
    refused: bool
    profile: str | None = None
    """The profile the query was checked for: what this server lets its callers see."""
    session_id: str | None = None
    """The session the request belongs to: this connection, or the server's one session for
    callers that have no connection (see session_of). The audit log records it, so
    `sql-warden audit tail --session <session_id>` lists everything the session asked."""
    check: str | None = None
    """The check that refused the query."""
    code: str | None = None
    reason: str | None = None
    sql: str | None = None
    """The SQL that ran, or would run: the checked query, regenerated, with any rewrites."""
    rewrites: list[str] = []
    masked_columns: list[MaskedColumnInfo] = []
    """The result's masked columns: their values come back masked, or would for a dry run."""
    cost: CostInfo | None = None
    """The planner's estimate, once the cost check got one: on an allowed query, and on one
    the cost check refused."""
    budget: BudgetInfo | None = None
    """What the session has used of its budget, this request included. Missing when the
    profile sets no limits."""
    trace: list[TraceStep]
    result: QueryRows | None = None
    error: str | None = None
    """Set when the query was allowed but the database failed to run it."""
    audit_id: str | None = None
    """This request's audit record. Missing only when it could not be written, and then the
    response is an AUDIT_UNAVAILABLE refusal."""


class ColumnInfo(BaseModel):
    name: str
    type: str
    mask: str | None = None
    """Set if the column comes back masked: redact, partial, hmac or null. A masked column
    can be selected as it is or counted, not filtered, joined, grouped, sorted or computed
    with, unless the profile allows it."""


class TableInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_name: str = Field(alias="schema")
    name: str
    columns: list[ColumnInfo]
    """Only the columns you may read."""
    all_columns: bool
    """True if you may read every column, including ones added later, so SELECT * works."""


class TableResponse(BaseModel):
    profile: str
    table: TableInfo


class TablesResponse(BaseModel):
    profile: str
    tables: list[TableInfo]


def json_value(value: object) -> Any:
    """A database value as JSON: exact numbers as strings, times in ISO 8601."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Decimal | uuid.UUID | datetime.timedelta):
        return str(value)
    if isinstance(value, datetime.date | datetime.time):
        return value.isoformat()
    if isinstance(value, bytes | bytearray | memoryview):
        return "\\x" + bytes(value).hex()
    if isinstance(value, list | tuple):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_value(item) for key, item in value.items()}
    return str(value)


def budget_info(status: BudgetStatus) -> BudgetInfo:
    lines = {
        what: BudgetLine(
            used=_number(used),
            limit=limit,
            remaining=None if limit is None else _number(max(limit - used, 0)),
        )
        for what, used, limit in status.lines()
    }
    return BudgetInfo(**lines, exhausted=status.exhausted)


def _number(value: float) -> float:
    return value if isinstance(value, int) else round(value, 2)


def describe_budget(warden: Warden, session_id: str | None = None) -> BudgetResponse:
    """What budget_status returns. A session whose usage can't be read is a tool error."""
    try:
        status = warden.budget_status(session_id)
    except SessionStoreError as exc:
        raise ToolError(f"this session's budget could not be read: {exc}") from exc
    return BudgetResponse(
        profile=warden.profile,
        session_id=session_id or warden.session_id,
        budget=budget_info(status),
    )


def describe(decision: Decision, outcome: QueryOutcome | None = None) -> QueryResponse:
    """The decision, and for run_query what happened when it ran, as the tools return it."""
    refused_by = decision.refused_by
    refusal = refused_by.refusal if refused_by else None
    result = outcome.result if outcome else None
    error = outcome.error if outcome else None
    return QueryResponse(
        refused=refusal is not None,
        profile=decision.profile,
        session_id=decision.session_id,
        check=refused_by.check if refused_by else None,
        code=refusal.code if refusal else None,
        reason=refusal.reason if refusal else None,
        sql=decision.sql,
        rewrites=list(decision.rewrites),
        masked_columns=[
            MaskedColumnInfo(
                column=masked.column,
                position=masked.position,
                strategy=masked.strategy,
                sources=list(masked.sources),
            )
            for masked in decision.masked
        ],
        cost=None
        if decision.cost is None or decision.cost_limit is None
        else CostInfo(
            total_cost=round(decision.cost.total_cost, 2),
            max_total_cost=decision.cost_limit,
            est_rows=decision.cost.est_rows,
            top_node=decision.cost.top_node,
            unit=decision.cost.unit,
        ),
        budget=None if decision.budget is None else budget_info(decision.budget),
        trace=[TraceStep.model_validate(trace_step(entry)) for entry in decision.trace],
        result=None
        if result is None
        else QueryRows(
            columns=list(result.columns),
            rows=[[json_value(value) for value in row] for row in result.rows],
            row_count=len(result.rows),
            truncated=result.truncated,
            duration_ms=round(result.duration_ms, 3),
        ),
        error=None if error is None else str(error),
        audit_id=None if decision.audit_id is None else str(decision.audit_id),
    )


def tool_result(response: QueryResponse, *, is_error: bool) -> CallToolResult:
    """The response as structured content, plus the same JSON as text for clients that only
    read text."""
    return CallToolResult(
        content=[TextContent(type="text", text=response.model_dump_json(exclude_none=True))],
        structured_content=response.model_dump(mode="json", exclude_none=True),
        is_error=is_error,
    )


def instructions(profile: str) -> str:
    """INSTRUCTIONS, plus which profile this server serves."""
    if profile == IMPLICIT_PROFILE:
        return INSTRUCTIONS + "\nNo access profiles are configured on this server."
    return INSTRUCTIONS + (
        f"\nThis server serves the '{profile}' profile; queries are checked against its rules. "
        "The profile is set when the server starts and can't be changed from here."
    )


def create_server(warden: Warden) -> MCPServer:
    server = MCPServer("sql-warden", version=__version__, instructions=instructions(warden.profile))

    @server.tool(annotations=READ_ONLY)
    def run_query(sql: str, ctx: Context[Any, Any]) -> Annotated[CallToolResult, QueryResponse]:
        """Run one read-only SQL SELECT and return its rows.

        The query is checked first. If a check refuses it, nothing runs and the result says
        which check, with a code and a reason. The result is an error when the query was
        refused or the database failed to run it.
        """
        outcome = warden.run(sql, client=client_name(ctx), session_id=session_of(ctx))
        return tool_result(describe(outcome.decision, outcome), is_error=outcome.result is None)

    @server.tool(annotations=READ_ONLY)
    def check_query(sql: str, ctx: Context[Any, Any]) -> Annotated[CallToolResult, QueryResponse]:
        """Dry run: say whether a SQL query would be allowed, its estimated cost, and the exact
        SQL that would run, without running it. The database only plans it."""
        decision = warden.check(sql, client=client_name(ctx), session_id=session_of(ctx))
        return tool_result(describe(decision), is_error=decision.audit_id is None)

    @server.tool(annotations=READ_ONLY)
    def budget_status(ctx: Context[Any, Any]) -> BudgetResponse:
        """What this session has used and what it has left: queries, their total estimated
        cost, rows returned and refusals. A limit that isn't set has no `limit`. Asking is
        free: it isn't a query, and is never refused."""
        return describe_budget(warden, session_of(ctx))

    @server.tool(annotations=READ_ONLY)
    def list_tables() -> TablesResponse:
        """List the tables and views you can query, with the columns you may read."""
        return describe_tables(warden)

    @server.tool(annotations=READ_ONLY)
    def describe_table(table: str) -> TableResponse:
        """Describe one table you can query: its columns and types, and whether SELECT * works.

        Name it as in SQL: `products` or `public.products`."""
        return describe_one_table(warden, table)

    return server


def client_name(ctx: Context[Any, Any]) -> str | None:
    """The client as it named itself when it connected, e.g. "claude-code 2.1.3", for the
    audit record. Self-reported, so a label, not an identity: identities come with auth."""
    params = ctx.session.client_params
    if params is None:
        return None
    return f"{params.client_info.name} {params.client_info.version}"


def session_of(ctx: Context[Any, Any]) -> str | None:
    """sql-warden's id for the session this request belongs to, or None for the Warden's own.

    Over HTTP a client that opens a connection (MCP before 2026-07-28: a handshake, then an
    Mcp-Session-Id on every request) has that connection as its session. Its id is derived
    from the transport's rather than being it: whoever holds the transport's id can use the
    connection, so it stays out of responses and the audit log.

    From 2026-07-28 on MCP has no connections over HTTP: each request stands alone, and
    nothing on it says which other requests came from the same caller. Those are all the
    Warden's own session, as stdio's one connection per process is. A limit then holds for
    the server as a whole, so it can't be got around; telling callers apart needs them to
    have identities, which comes with authentication."""
    headers = ctx.headers
    transport_id = None if headers is None else headers.get(MCP_SESSION_ID_HEADER)
    if not transport_id:
        return None
    return hashlib.sha256(b"sql-warden session " + transport_id.encode()).hexdigest()[:32]


def table_info(warden: Warden, table: Table) -> TableInfo:
    return TableInfo(
        schema_name=table.schema,
        name=table.name,
        columns=[
            ColumnInfo(
                name=c.name,
                type=c.type,
                mask=rule.strategy
                if (rule := warden.masks.get((table.schema, table.name, c.name)))
                else None,
            )
            for c in table.columns
        ],
        all_columns=warden.all_columns(table),
    )


def describe_tables(warden: Warden) -> TablesResponse:
    """What list_tables returns. Engine errors become tool errors."""
    try:
        tables = warden.tables()
    except EngineError as exc:
        # Engine messages are safe to show; anything else stays hidden by the SDK.
        raise ToolError(str(exc)) from exc
    return TablesResponse(
        profile=warden.profile, tables=[table_info(warden, table) for table in tables]
    )


def describe_one_table(warden: Warden, name: str) -> TableResponse:
    """What describe_table returns. A table the profile may not read gets the same error as
    one that doesn't exist."""
    try:
        table = warden.table(name)
    except EngineError as exc:
        raise ToolError(str(exc)) from exc
    if table is None:
        raise ToolError(f"table {name} is not available to profile {warden.profile}")
    return TableResponse(profile=warden.profile, table=table_info(warden, table))


def create_http_app(
    warden: Warden,
    *,
    host: str = "127.0.0.1",
    max_sessions: int = MAX_SESSIONS,
    session_idle_s: float = SESSION_IDLE_S,
) -> Starlette:
    """The MCP server as an ASGI app, serving Streamable HTTP at /mcp.

    Requests must name a loopback host and, from a browser, a loopback origin, which stops a
    web page from reaching the server through DNS rebinding.

    Each connection is a session of its own, with its own budget. At most max_sessions are
    open at once (one more is answered 503 until one closes), and one that sends nothing
    for session_idle_s is closed. Queries run in worker threads, so a slow one holds up
    nobody else's.
    """
    if not is_loopback(host):
        raise ValueError(f"refusing to serve MCP over HTTP on {host}: {LOOPBACK_ONLY}")
    names = ["127.0.0.1", "localhost", "[::1]"]
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[f"{name}:*" for name in names],
        allowed_origins=[f"http://{name}:*" for name in names],
    )
    return create_server(warden).streamable_http_app(
        transport_security=security,
        host=host,
        max_request_body_size=MAX_REQUEST_BYTES,
        max_sessions=max_sessions,
        session_idle_timeout=session_idle_s,
    )
