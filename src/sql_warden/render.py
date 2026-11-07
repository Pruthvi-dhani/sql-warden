"""Plain-text output for the CLI."""

import dataclasses
import re
from typing import Any

from sql_warden.audit import AuditEvent
from sql_warden.engines import Result
from sql_warden.models import Decision
from sql_warden.pipeline.cost import format_cost
from sql_warden.server import TableResponse, TablesResponse


def format_decision(decision: Decision, *, dry_run: bool) -> str:
    """One line per check that ran, then the verdict and anything the checks rewrote."""
    width = max(len(entry.check) for entry in decision.trace)
    lines = []
    for entry in decision.trace:
        if entry.refusal is None:
            lines.append(f"✓ {entry.check.ljust(width)}  {entry.duration_ms:.1f} ms")
        else:
            refusal = entry.refusal
            lines.append(f"✗ {entry.check.ljust(width)}  {refusal.code}: {refusal.reason}")
    refused_by = decision.refused_by
    profile = f"profile {decision.profile}" if decision.profile else None
    if refused_by is not None:
        lines.append(f"→ refused by {refused_by.check}" + (f" ({profile})" if profile else ""))
    elif dry_run:
        lines.append(
            "→ allowed (" + (f"{profile}; " if profile else "") + "dry run, nothing was executed)"
        )
    else:
        lines.append("→ allowed" + (f" ({profile})" if profile else ""))
    if decision.allowed:
        lines += format_cost_line(decision)
    lines += [f"  {note}" for note in format_rewrites(decision)]
    if dry_run and decision.sql is not None:
        lines.append(f"  would run: {decision.sql}")
    return "\n".join(lines)


def format_cost_line(decision: Decision) -> list[str]:
    """The planner's estimate against the limit, for an allowed query. A refusal by the cost
    check says it in its reason."""
    cost, limit = decision.cost, decision.cost_limit
    if cost is None or limit is None:
        return []
    return [
        f"  cost: {format_cost(cost.total_cost)} of {format_cost(limit)} allowed "
        f"(most of it: {cost.top_node})"
    ]


def format_rewrites(decision: Decision) -> list[str]:
    return [f"note: {rewrite}" for rewrite in decision.rewrites]


def format_value(value: object) -> str:
    return "NULL" if value is None else str(value)


def format_table(result: Result, *, profile: str | None = None) -> str:
    cells = [[format_value(v) for v in row] for row in result.rows]
    widths = [len(name) for name in result.columns]
    for row in cells:
        widths = [max(w, len(cell)) for w, cell in zip(widths, row, strict=True)]

    def line(values: list[str]) -> str:
        return " | ".join(v.ljust(w) for v, w in zip(values, widths, strict=True)).rstrip()

    lines = [line(list(result.columns)), "-+-".join("-" * w for w in widths)]
    lines += [line(row) for row in cells]
    lines.append(format_footer(result, profile=profile))
    return "\n".join(lines)


def format_footer(result: Result, *, profile: str | None = None) -> str:
    count = len(result.rows)
    footer = f"({count} row{'' if count == 1 else 's'}"
    if result.truncated:
        footer += ", truncated at the row cap"
    footer += f", {result.duration_ms:.0f} ms"
    return footer + (f", profile {profile})" if profile else ")")


def format_tables(response: TablesResponse) -> str:
    """One line per table with the columns the profile may read."""
    names = [f"{table.schema_name}.{table.name}" for table in response.tables]
    width = max((len(name) for name in names), default=0)
    lines = [
        f"{name.ljust(width)}  {', '.join(c.name for c in table.columns)}"
        + ("" if table.all_columns else "  (some columns)")
        for name, table in zip(names, response.tables, strict=True)
    ]
    count = len(response.tables)
    lines.append(f"({count} table{'' if count == 1 else 's'}, profile {response.profile})")
    return "\n".join(lines)


def format_table_detail(response: TableResponse) -> str:
    table = response.table
    width = max(len(column.name) for column in table.columns)
    lines = [f"{table.schema_name}.{table.name} (profile {response.profile})"]
    lines += [f"  {column.name.ljust(width)}  {column.type}" for column in table.columns]
    lines.append(
        "SELECT * is allowed"
        if table.all_columns
        else "SELECT * is not allowed: the profile may read only these columns, so name them"
    )
    return "\n".join(lines)


# audit tail: fixed widths, so lines printed later by --follow line up with the first ones.
_AUDIT_COLUMNS = (("ID", 8), ("TIME", 19), ("KIND", 5), ("PROFILE", 8), ("CLIENT", 16))
_RESULT_WIDTH = 27
_SQL_WIDTH = 60
AUDIT_HEADER = "  ".join(
    [*(name.ljust(width) for name, width in _AUDIT_COLUMNS), "RESULT".ljust(_RESULT_WIDTH), "SQL"]
)


def _clip(text: str, width: int) -> str:
    """text, cut to width characters with an ellipsis if longer."""
    return text if len(text) <= width else text[: width - 1] + "…"


def _fit(text: str, width: int) -> str:
    """text in exactly width characters: padded, or cut with an ellipsis."""
    return _clip(text, width).ljust(width)


def _one_line(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()


def _rows(count: int) -> str:
    return f"{count} row{'' if count == 1 else 's'}"


def audit_result(event: AuditEvent) -> str:
    """What came of the request, in a few words."""
    if event.decision == "refused":
        return f"refused {event.code}"
    if event.decision == "failed":
        return "failed"
    if event.dry_run:
        return "allowed"
    rows = _rows(event.rows_returned or 0)
    return f"{rows}, truncated" if event.truncated else rows


def format_audit_line(event: AuditEvent) -> str:
    """One event as a line of audit tail, under AUDIT_HEADER."""
    values = (
        str(event.id)[:8],
        event.ts.astimezone().strftime("%Y-%m-%d %H:%M:%S"),
        "check" if event.dry_run else "query",
        event.profile,
        event.client or "-",
    )
    cells = [_fit(value, width) for value, (_, width) in zip(values, _AUDIT_COLUMNS, strict=True)]
    cells.append(_fit(audit_result(event), _RESULT_WIDTH))
    cells.append(_clip(_one_line(event.sql), _SQL_WIDTH))
    return "  ".join(cells)


def format_audit_event(event: AuditEvent) -> str:
    """Everything recorded about one request, for audit show."""
    lines = [f"event    {event.id}"]
    lines.append(f"time     {event.ts.astimezone().isoformat(sep=' ', timespec='milliseconds')}")
    lines.append(f"profile  {event.profile}")
    lines.append(f"client   {event.client or '-'}")
    if event.session_id is not None:
        lines.append(f"session  {event.session_id}")
    kind = "check (dry run, nothing was executed)" if event.dry_run else "query"
    lines.append(f"kind     {kind}")
    if event.decision == "refused":
        result = f"refused by {event.refused_by}: {event.code}"
    elif event.decision == "failed":
        result = f"failed: {event.error}"
    elif event.dry_run:
        result = "allowed"
    else:
        result = f"allowed, {audit_result(event)}"
    lines.append(f"result   {result} ({event.duration_ms:.0f} ms)")
    if event.cost_estimate is not None:
        lines.append(f"cost     {format_cost(event.cost_estimate)}")
    if event.masked_columns:
        lines.append(f"masked   {', '.join(event.masked_columns)}")
    lines.append("sql, as sent:")
    lines += [f"  {line}" for line in event.sql.strip().splitlines()]
    if event.executed_sql is not None:
        lines.append("sql, as it would run:" if event.dry_run else "sql, as run:")
        lines.append(f"  {event.executed_sql}")
    lines += [f"note: {rewrite}" for rewrite in event.rewrites]
    lines.append("trace:")
    width = max((len(str(step["check"])) for step in event.trace), default=0)
    for step in event.trace:
        name = str(step["check"]).ljust(width)
        if step["passed"]:
            lines.append(f"  ✓ {name}  {float(step['duration_ms']):.1f} ms")
        else:
            lines.append(f"  ✗ {name}  {step['code']}: {step['reason']}")
    return "\n".join(lines)


def audit_json(event: AuditEvent) -> dict[str, Any]:
    """One event as JSON: the audit_events row, with the id and time as strings."""
    return {
        **dataclasses.asdict(event),
        "id": str(event.id),
        "ts": event.ts.isoformat(),
        "rewrites": list(event.rewrites),
        "masked_columns": list(event.masked_columns),
        "trace": list(event.trace),
    }
