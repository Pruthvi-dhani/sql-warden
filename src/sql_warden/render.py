"""Plain-text output for the CLI."""

from sql_warden.engines import Result


def format_value(value: object) -> str:
    return "NULL" if value is None else str(value)


def format_table(result: Result) -> str:
    cells = [[format_value(v) for v in row] for row in result.rows]
    widths = [len(name) for name in result.columns]
    for row in cells:
        widths = [max(w, len(cell)) for w, cell in zip(widths, row, strict=True)]

    def line(values: list[str]) -> str:
        return " | ".join(v.ljust(w) for v, w in zip(values, widths, strict=True)).rstrip()

    lines = [line(list(result.columns)), "-+-".join("-" * w for w in widths)]
    lines += [line(row) for row in cells]
    lines.append(format_footer(result))
    return "\n".join(lines)


def format_footer(result: Result) -> str:
    count = len(result.rows)
    footer = f"({count} row{'' if count == 1 else 's'}"
    if result.truncated:
        footer += ", truncated at the row cap"
    return footer + f", {result.duration_ms:.0f} ms)"
