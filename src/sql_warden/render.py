"""Plain-text output for the CLI."""

from sql_warden.engines import Result
from sql_warden.models import Decision
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
    lines += [f"  {note}" for note in format_rewrites(decision)]
    if dry_run and decision.sql is not None:
        lines.append(f"  would run: {decision.sql}")
    return "\n".join(lines)


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
