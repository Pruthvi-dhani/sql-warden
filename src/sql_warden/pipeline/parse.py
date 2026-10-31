import re

import sqlglot
from sqlglot.errors import ParseError

from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline.base import CheckContext

# sqlglot error descriptions embed Python reprs; reword them for the person or agent reading.
_TOKEN_REPR = re.compile(r"<Token token_type: [^,]+, text: (.*?), line: .*?>")
_MISSING_PART = re.compile(r"Required keyword: '\w+' missing for <class '[\w.]*\.(\w+)'>")
_CLAUSE_NAMES = {"Order": "ORDER BY", "Group": "GROUP BY"}


def _clause_name(node_class: str) -> str:
    return _CLAUSE_NAMES.get(node_class, node_class.upper())


def describe_parse_error(error: ParseError) -> str:
    if not error.errors:
        return str(error)
    first = error.errors[0]
    description = _TOKEN_REPR.sub(
        lambda m: "end of query" if m.group(1) == "SENTINEL" else repr(m.group(1)),
        str(first["description"]),
    )
    description = _MISSING_PART.sub(
        lambda m: f"incomplete {_clause_name(m.group(1))} clause", description
    )
    return f"{description} (line {first['line']}, col {first['col']})"


class ParseCheck:
    name = "parse"

    def run(self, ctx: CheckContext) -> Refusal | None:
        try:
            parsed = sqlglot.parse(ctx.sql, dialect=ctx.dialect)
        except ParseError as exc:
            return Refusal(RefusalCode.PARSE_ERROR, describe_parse_error(exc))
        ctx.statements = [statement for statement in parsed if statement is not None]
        if not ctx.statements:
            return Refusal(RefusalCode.PARSE_ERROR, "the query is empty")
        return None
