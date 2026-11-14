"""The MCP server: how agents reach the warden.

Over stdio for an agent that launches sql-warden itself, or over HTTP. Without
authentication HTTP serves one profile, on loopback only. With it (an Authenticator), one
server serves every profile: each request carries a bearer token, and the token says who
the caller is and which profile its queries are checked against.
"""

import datetime
import hashlib
import json
import logging
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager, suppress
from decimal import Decimal
from typing import Annotated, Any

import anyio.to_thread
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.streamable_http import MCP_SESSION_ID_HEADER
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import BaseRoute, Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from sql_warden import __version__
from sql_warden.audit import AuditEvent, AuditSink
from sql_warden.auth import Authenticator, AuthError, Identity
from sql_warden.config import IMPLICIT_PROFILE, LOOPBACK_ONLY, is_loopback
from sql_warden.engines import EngineError, Table
from sql_warden.metrics import CONTENT_TYPE as METRICS_TYPE
from sql_warden.metrics import Metrics
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
    caller: "CallerBudgetInfo | None" = None
    """The caller's budget over the window, across all their sessions: with a token, where
    the profile sets one. Whichever runs out first refuses."""


class CallerBudgetInfo(BaseModel):
    identity: str
    window_hours: float
    """Use counts for this long: a budget for any 24 hours, say."""
    queries: BudgetLine
    total_cost: BudgetLine
    rows_returned: BudgetLine
    refusals: BudgetLine
    exhausted: str | None = None
    """The limit the caller has reached. Then nothing more runs for them, in any session,
    until enough of their use is older than the window."""


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


def _lines(lines: tuple[tuple[str, float, float | None], ...]) -> dict[str, BudgetLine]:
    return {
        what: BudgetLine(
            used=_number(used),
            limit=limit,
            remaining=None if limit is None else _number(max(limit - used, 0)),
        )
        for what, used, limit in lines
    }


def budget_info(status: BudgetStatus) -> BudgetInfo:
    caller = status.caller
    theirs = (
        None
        if caller is None
        else CallerBudgetInfo(
            identity=caller.name,
            window_hours=caller.window_hours,
            **_lines(caller.lines()),
            exhausted=caller.exhausted,
        )
    )
    return BudgetInfo(**_lines(status.lines()), exhausted=status.exhausted, caller=theirs)


def _number(value: float) -> float:
    return value if isinstance(value, int) else round(value, 2)


def describe_budget(
    warden: Warden, session_id: str | None = None, identity: str | None = None
) -> BudgetResponse:
    """What budget_status returns. A session whose usage can't be read is a tool error."""
    try:
        status = warden.budget_status(session_id, identity)
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


IDENTITY = "sql_warden.identity"
"""Where RequireToken leaves the caller's Identity in the request's ASGI scope."""
MULTI_PROFILE = (
    "\nWhich profile your queries are checked against comes from your token, and every "
    "result names it. It can't be changed from here."
)


def create_server(wardens: Warden | Mapping[str, Warden]) -> MCPServer:
    """The MCP tools, for one Warden, or for one per profile (by name) when callers
    authenticate: then each request is answered by its caller's profile's Warden."""
    nonce = secrets.token_hex(16)
    if isinstance(wardens, Warden):
        only = wardens
        pick: Callable[[Identity | None], Warden] = lambda identity: only  # noqa: E731
        text = instructions(only.profile)
    else:
        by_profile = dict(wardens)
        if not by_profile:
            raise ValueError("a server needs at least one profile to serve")

        def pick(identity: Identity | None) -> Warden:
            if identity is None or identity.profile not in by_profile:
                # RequireToken lets no such request through; this is the last line.
                raise ToolError("this server answers only requests that carry a token")
            return by_profile[identity.profile]

        text = INSTRUCTIONS + MULTI_PROFILE
    server = MCPServer("sql-warden", version=__version__, instructions=text)

    def caller(ctx: Context[Any, Any]) -> tuple[Warden, Identity | None, str | None]:
        """Who is asking: the Warden for their profile, their identity, their session."""
        identity = identity_of(ctx)
        return pick(identity), identity, session_of(ctx, identity, nonce=nonce)

    @server.tool(annotations=READ_ONLY)
    def run_query(sql: str, ctx: Context[Any, Any]) -> Annotated[CallToolResult, QueryResponse]:
        """Run one read-only SQL SELECT and return its rows.

        The query is checked first. If a check refuses it, nothing runs and the result says
        which check, with a code and a reason. The result is an error when the query was
        refused or the database failed to run it.
        """
        warden, identity, session_id = caller(ctx)
        outcome = warden.run(
            sql, client=client_name(ctx), session_id=session_id, identity=_name(identity)
        )
        return tool_result(describe(outcome.decision, outcome), is_error=outcome.result is None)

    @server.tool(annotations=READ_ONLY)
    def check_query(sql: str, ctx: Context[Any, Any]) -> Annotated[CallToolResult, QueryResponse]:
        """Dry run: say whether a SQL query would be allowed, its estimated cost, and the exact
        SQL that would run, without running it. The database only plans it."""
        warden, identity, session_id = caller(ctx)
        decision = warden.check(
            sql, client=client_name(ctx), session_id=session_id, identity=_name(identity)
        )
        return tool_result(describe(decision), is_error=decision.audit_id is None)

    @server.tool(annotations=READ_ONLY)
    def budget_status(ctx: Context[Any, Any]) -> BudgetResponse:
        """What this session has used and what it has left: queries, their total estimated
        cost, rows returned and refusals. A limit that isn't set has no `limit`. Asking is
        free: it isn't a query, and is never refused."""
        warden, identity, session_id = caller(ctx)
        return describe_budget(warden, session_id, _name(identity))

    @server.tool(annotations=READ_ONLY)
    def list_tables(ctx: Context[Any, Any]) -> TablesResponse:
        """List the tables and views you can query, with the columns you may read."""
        return describe_tables(caller(ctx)[0])

    @server.tool(annotations=READ_ONLY)
    def describe_table(table: str, ctx: Context[Any, Any]) -> TableResponse:
        """Describe one table you can query: its columns and types, and whether SELECT * works.

        Name it as in SQL: `products` or `public.products`."""
        return describe_one_table(caller(ctx)[0], table)

    return server


def _name(identity: Identity | None) -> str | None:
    return None if identity is None else identity.name


def identity_of(ctx: Context[Any, Any]) -> Identity | None:
    """The caller RequireToken let in, or None where nobody authenticates (stdio, or HTTP
    without an auth section)."""
    scope = getattr(ctx.request_context.request, "scope", None)
    identity = scope.get(IDENTITY) if isinstance(scope, dict) else None
    return identity if isinstance(identity, Identity) else None


def client_name(ctx: Context[Any, Any]) -> str | None:
    """The client as it named itself when it connected, e.g. "claude-code 2.1.3", for the
    audit record. Self-reported, so a label, not an identity: identities come with auth."""
    params = ctx.session.client_params
    if params is None:
        return None
    return f"{params.client_info.name} {params.client_info.version}"


def session_of(
    ctx: Context[Any, Any], identity: Identity | None = None, *, nonce: str = ""
) -> str | None:
    """sql-warden's id for the session this request belongs to, or None for the Warden's own.

    Over HTTP a client that opens a connection (MCP before 2026-07-28: a handshake, then an
    Mcp-Session-Id on every request) has that connection as its session. Its id is derived
    from the transport's rather than being it: whoever holds the transport's id can use the
    connection, so it stays out of responses and the audit log. With authentication the
    transport also keeps the connection to the caller who opened it.

    From 2026-07-28 on MCP has no connections over HTTP: each request stands alone. A caller
    who authenticated then has one session of their own, for as long as this server runs
    (nonce is the server's: a restarted server starts everyone's afresh, as it does for
    connections). Without authentication nothing tells such callers apart, and they are all
    the Warden's own session, as stdio's one connection per process is."""
    headers = ctx.headers
    transport_id = None if headers is None else headers.get(MCP_SESSION_ID_HEADER)
    if transport_id:
        return _derived("session", transport_id)
    if identity is not None:
        return _derived("caller", f"{nonce}:{identity.name}")
    return None


def _derived(kind: str, value: str) -> str:
    return hashlib.sha256(f"sql-warden {kind} {value}".encode()).hexdigest()[:32]


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


NO_STORE = {"Cache-Control": "no-store"}
READY_FOR_S = 10.0
"""How long a readiness answer is reused: probes come every few seconds, and asking every
profile's role each time would be a load of its own."""
log = logging.getLogger("sql_warden.server")


class Readiness:
    """Whether the server can answer: each check raises if what it looks at can't be used.
    The answer is kept READY_FOR_S seconds, and reasons are logged rather than sent: whoever
    can reach /readyz learns only which checks fail."""

    def __init__(
        self,
        checks: Mapping[str, Callable[[], None]],
        *,
        ready_for_s: float = READY_FOR_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._checks = dict(checks)
        self._ready_for_s = ready_for_s
        self._clock = clock
        self._answer: tuple[float, list[str]] | None = None
        self._lock = anyio.Lock()

    async def failing(self) -> list[str]:
        async with self._lock:  # one probe asks; any at the same time wait for its answer
            now = self._clock()
            if self._answer is not None and now - self._answer[0] < self._ready_for_s:
                return list(self._answer[1])
            failing = []
            for name, check in self._checks.items():
                try:
                    await anyio.to_thread.run_sync(check)
                except Exception as exc:
                    log.warning("not ready: %s: %s", name, exc)
                    failing.append(name)
            self._answer = (self._clock(), failing)
            return list(failing)


def create_http_app(
    wardens: Warden | Mapping[str, Warden],
    *,
    host: str = "127.0.0.1",
    authenticator: Authenticator | None = None,
    allowed_hosts: Sequence[str] = (),
    allowed_origins: Sequence[str] = (),
    max_sessions: int = MAX_SESSIONS,
    session_idle_s: float = SESSION_IDLE_S,
    metrics: Metrics | None = None,
    readiness: Readiness | None = None,
    max_concurrent_requests: int | None = None,
) -> Starlette:
    """The MCP server as an ASGI app, serving Streamable HTTP at /mcp.

    Beside it, needing no token: /healthz (the process answers), /readyz (readiness's checks
    pass; without any, the same as /healthz) and, given metrics, /metrics for Prometheus.
    max_concurrent_requests caps the worker threads requests are answered in, so no more
    than that many reach the databases at once; the rest wait their turn.

    Without an authenticator it serves one Warden, on loopback only. With one, every request
    must carry a bearer token (see RequireToken), wardens may be one per profile, and host
    may be any: allowed_hosts are then the names clients reach it by.

    Requests must name a loopback host or one of allowed_hosts and, from a browser, a
    loopback origin or one of allowed_origins, which stops a web page from reaching the
    server through DNS rebinding.

    Each connection is a session of its own, with its own budget. At most max_sessions are
    open at once (one more is answered 503 until one closes), and one that sends nothing
    for session_idle_s is closed. Queries run in worker threads, so a slow one holds up
    nobody else's.
    """
    if authenticator is None:
        if not isinstance(wardens, Warden):
            raise ValueError(
                "serving more than one profile needs authentication: a token is what says "
                "which profile a request gets"
            )
        if not is_loopback(host):
            raise ValueError(f"refusing to serve MCP over HTTP on {host}: {LOOPBACK_ONLY}")
        if allowed_hosts or allowed_origins:
            raise ValueError("allowed_hosts and allowed_origins come with authentication")
    elif not is_loopback(host) and not allowed_hosts:
        raise ValueError(
            f"serving on {host}, which other machines can reach: give allowed_hosts, the "
            "names clients reach the server by"
        )
    names = ["127.0.0.1", "localhost", "[::1]"]
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[f"{name}:*" for name in names]
        + [form for name in allowed_hosts for form in (name, f"{name}:*")],
        allowed_origins=[f"http://{name}:*" for name in names] + list(allowed_origins),
    )
    app = create_server(wardens).streamable_http_app(
        transport_security=security,
        host=host,
        max_request_body_size=MAX_REQUEST_BYTES,
        max_sessions=max_sessions,
        session_idle_timeout=session_idle_s,
    )
    if authenticator is not None:
        first = wardens if isinstance(wardens, Warden) else next(iter(wardens.values()))
        app.add_middleware(
            RequireToken, authenticator=authenticator, audit=first.audit, metrics=metrics
        )
    return _with_health(app, metrics, readiness or Readiness({}), max_concurrent_requests)


def _with_health(
    mcp: Starlette, metrics: Metrics | None, readiness: Readiness, workers: int | None
) -> Starlette:
    async def healthz(request: Request) -> Response:
        return PlainTextResponse("ok\n", headers=NO_STORE)

    async def readyz(request: Request) -> Response:
        failing = await readiness.failing()
        body = {"ready": not failing, "failing": failing}
        return JSONResponse(body, status_code=503 if failing else 200, headers=NO_STORE)

    async def scrape(request: Request) -> Response:
        assert metrics is not None
        return Response(metrics.render(), media_type=METRICS_TYPE, headers=NO_STORE)

    routes: list[BaseRoute] = [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/readyz", readyz, methods=["GET"]),
    ]
    if metrics is not None:
        routes.append(Route("/metrics", scrape, methods=["GET"]))
    routes.append(Mount("/", app=mcp))

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        if workers is not None:
            # Tool calls run in these threads, and each holds a database connection.
            anyio.to_thread.current_default_thread_limiter().total_tokens = workers
        async with mcp.router.lifespan_context(mcp):
            yield

    return Starlette(routes=routes, lifespan=lifespan)


REALM = "sql-warden"
USER_AGENT_CHARS = 200


class RequireToken:
    """Lets an HTTP request through only with `Authorization: Bearer <token>` for a caller
    the Authenticator knows, and tells the rest of the server who that is.

    A request turned away is answered 401 (no token, or not a valid one), 403 (a valid token
    that gives no profile) or 503 (the provider's keys couldn't be fetched), and is recorded
    in the audit log as refused by `auth`. Its body is never read: nothing it asked for is
    known, or done.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        authenticator: Authenticator,
        audit: AuditSink,
        metrics: Metrics | None = None,
    ) -> None:
        self.app = app
        self.authenticator = authenticator
        self.audit = audit
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        token = _bearer(scope)
        try:
            if token is None:
                raise AuthError("this server needs a token: send Authorization: Bearer <token>")
            identity = await anyio.to_thread.run_sync(self.authenticator.authenticate, token)
        except AuthError as exc:
            if self.metrics is not None:
                self.metrics.auth_refusals.inc(code=str(exc.code))
            await anyio.to_thread.run_sync(self._record, scope, exc, started)
            await _refuse(send, exc, asked=token is not None)
            return
        # The transport keeps each connection to the caller who opened it, by this.
        scope["user"] = AuthenticatedUser(
            AccessToken(
                token=identity.name,  # what the SDK keeps of it: never the token itself
                client_id=identity.name,
                scopes=[],
                subject=identity.name,
                claims={"iss": REALM},
            )
        )
        scope[IDENTITY] = identity
        await self.app(scope, receive, send)

    def _record(self, scope: Scope, refusal: AuthError, started: float) -> None:
        duration_ms = (time.perf_counter() - started) * 1000
        step = {
            "check": "auth",
            "passed": False,
            "code": str(refusal.code),
            "reason": str(refusal),
            "duration_ms": duration_ms,
        }
        agent = _header(scope, b"user-agent")
        event = AuditEvent(
            profile=None,
            sql="",
            decision="refused",
            duration_ms=duration_ms,
            trace=(step,),
            refused_by="auth",
            code=str(refusal.code),
            reason=str(refusal),
            client=None if agent is None else agent[:USER_AGENT_CHARS],
            identity=refusal.who,
        )
        with suppress(Exception):  # refused either way, and nothing was done to need a record
            self.audit.record(event)


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", ()):
        if bytes(key).lower() == name:
            return bytes(value).decode("latin-1")
    return None


def _bearer(scope: Scope) -> str | None:
    value = _header(scope, b"authorization")
    if value is None:
        return None
    scheme, _, token = value.partition(" ")
    token = token.strip()
    return token if scheme.lower() == "bearer" and token else None


async def _refuse(send: Send, refusal: AuthError, *, asked: bool) -> None:
    """The answer to a request RequireToken turns away, as RFC 6750 has it."""
    description = "".join(c for c in str(refusal) if c.isprintable() and c not in '"\\')
    headers = [(b"content-type", b"application/json")]
    if refusal.status in (401, 403):
        # Without a token there is no error to name, only the scheme to use.
        challenge = f'Bearer realm="{REALM}"'
        if asked:
            challenge += f', error="{refusal.error}", error_description="{description}"'
        headers.append((b"www-authenticate", challenge.encode("latin-1", "replace")))
    else:
        headers.append((b"retry-after", b"60"))
    body = json.dumps(
        {"error": refusal.error, "error_description": str(refusal), "code": str(refusal.code)}
    ).encode()
    headers.append((b"content-length", str(len(body)).encode()))
    await send({"type": "http.response.start", "status": refusal.status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
