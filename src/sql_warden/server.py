"""The MCP server: how agents reach the warden.

Over stdio for an agent that launches sql-warden itself, or over HTTP on the loopback
interface for local tools such as the test portal. The HTTP transport has no authentication
yet, so it never listens anywhere else.
"""

import datetime
import ipaddress
import uuid
from decimal import Decimal
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import CallToolResult, TextContent, ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field
from starlette.applications import Starlette

from sql_warden import __version__
from sql_warden.engines import EngineError
from sql_warden.models import Decision, QueryOutcome
from sql_warden.warden import Warden

INSTRUCTIONS = """\
sql-warden runs read-only SQL against a governed database. Every query goes through checks
before it runs; a refused query comes back with the check, a code and a reason, so you can
fix it and try again. Only single SELECT statements are allowed. Results are capped: if a
query has no LIMIT, or one above the cap, sql-warden adds or lowers it and says so in
`rewrites`; `truncated` tells you whether rows were cut off. Use list_tables to see what you
can query and check_query to test a query without running it."""

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)
LOOPBACK_NAMES = ("localhost",)


class TraceStep(BaseModel):
    check: str
    passed: bool
    code: str | None = None
    reason: str | None = None
    duration_ms: float


class QueryRows(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    row_count: int
    truncated: bool
    """True when the query produced more rows than the row cap; only the first ones are here."""
    duration_ms: float


class QueryResponse(BaseModel):
    refused: bool
    check: str | None = None
    """The check that refused the query."""
    code: str | None = None
    reason: str | None = None
    sql: str | None = None
    """The SQL that ran, or would run: the checked query, regenerated, with any rewrites."""
    rewrites: list[str] = []
    trace: list[TraceStep]
    result: QueryRows | None = None
    error: str | None = None
    """Set when the query was allowed but the database failed to run it."""


class ColumnInfo(BaseModel):
    name: str
    type: str


class TableInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_name: str = Field(alias="schema")
    name: str
    columns: list[ColumnInfo]


class TablesResponse(BaseModel):
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


def describe(decision: Decision, outcome: QueryOutcome | None = None) -> QueryResponse:
    """The decision, and for run_query what happened when it ran, as the tools return it."""
    refused_by = decision.refused_by
    refusal = refused_by.refusal if refused_by else None
    result = outcome.result if outcome else None
    error = outcome.error if outcome else None
    return QueryResponse(
        refused=refusal is not None,
        check=refused_by.check if refused_by else None,
        code=refusal.code if refusal else None,
        reason=refusal.reason if refusal else None,
        sql=decision.sql,
        rewrites=list(decision.rewrites),
        trace=[
            TraceStep(
                check=entry.check,
                passed=entry.passed,
                code=entry.refusal.code if entry.refusal else None,
                reason=entry.refusal.reason if entry.refusal else None,
                duration_ms=round(entry.duration_ms, 3),
            )
            for entry in decision.trace
        ],
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
    )


def tool_result(response: QueryResponse, *, is_error: bool) -> CallToolResult:
    """The response as structured content, plus the same JSON as text for clients that only
    read text."""
    return CallToolResult(
        content=[TextContent(type="text", text=response.model_dump_json(exclude_none=True))],
        structured_content=response.model_dump(mode="json", exclude_none=True),
        is_error=is_error,
    )


def create_server(warden: Warden) -> MCPServer:
    server = MCPServer("sql-warden", version=__version__, instructions=INSTRUCTIONS)

    @server.tool(annotations=READ_ONLY)
    def run_query(sql: str) -> Annotated[CallToolResult, QueryResponse]:
        """Run one read-only SQL SELECT and return its rows.

        The query is checked first. If a check refuses it, nothing runs and the result says
        which check, with a code and a reason. The result is an error when the query was
        refused or the database failed to run it.
        """
        outcome = warden.run(sql)
        return tool_result(describe(outcome.decision, outcome), is_error=outcome.result is None)

    @server.tool(annotations=READ_ONLY)
    def check_query(sql: str) -> Annotated[CallToolResult, QueryResponse]:
        """Dry run: say whether a SQL query would be allowed, and the exact SQL that would run,
        without touching the database."""
        return tool_result(describe(warden.check(sql)), is_error=False)

    @server.tool(annotations=READ_ONLY)
    def list_tables() -> TablesResponse:
        """List the tables and views you can query, with their columns and types."""
        try:
            tables = warden.tables()
        except EngineError as exc:
            # Engine messages are safe to show; anything else stays hidden by the SDK.
            raise ToolError(str(exc)) from exc
        return TablesResponse(
            tables=[
                TableInfo(
                    schema_name=table.schema,
                    name=table.name,
                    columns=[ColumnInfo(name=c.name, type=c.type) for c in table.columns],
                )
                for table in tables
            ]
        )

    return server


def is_loopback(host: str) -> bool:
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def create_http_app(warden: Warden, *, host: str = "127.0.0.1") -> Starlette:
    """The MCP server as an ASGI app, serving Streamable HTTP at /mcp.

    Requests must name a loopback host and, from a browser, a loopback origin, which stops a
    web page from reaching the server through DNS rebinding.
    """
    if not is_loopback(host):
        raise ValueError(
            f"refusing to serve MCP over HTTP on {host}: there is no authentication yet, so "
            "it only listens on loopback (127.0.0.1, ::1 or localhost)"
        )
    names = ["127.0.0.1", "localhost", "[::1]"]
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[f"{name}:*" for name in names],
        allowed_origins=[f"http://{name}:*" for name in names],
    )
    return create_server(warden).streamable_http_app(transport_security=security, host=host)
