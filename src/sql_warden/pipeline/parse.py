import re
from collections.abc import Collection, Iterable

from sqlglot import Token, TokenType
from sqlglot.dialects.dialect import Dialect
from sqlglot.errors import ParseError, TokenError

from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline.base import CheckContext

MAX_LENGTH = 20_000
"""Characters in a query. Past this it is not read at all: the time the checks take grows
with the query, and no query an agent writes is this long."""
MAX_NESTING = 32
"""How deep brackets may nest: ((...)), f(g(...)), [[...]]. The parser calls itself once or
more per level, and runs out of stack not far past this."""
MAX_TYPE_NESTING = 4
"""How deep brackets that follow a type's name may nest: date(date(...)), array[array[...]].
The parser reads what is inside each of those twice, once as a type and again as an
expression, so every level doubles its work: thirty levels would take it hours."""

_OPENING = {TokenType.L_PAREN, TokenType.L_BRACKET, TokenType.L_BRACE}
_CLOSING = {TokenType.R_PAREN, TokenType.R_BRACKET, TokenType.R_BRACE}
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


def _is_text(sql: str) -> bool:
    try:
        sql.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def nesting(tokens: Iterable[Token], type_tokens: Collection[TokenType]) -> tuple[int, int]:
    """How deep the brackets in tokens nest, and how deep those that follow a type's name
    do, counting each of those wherever it sits among the others."""
    deepest = deepest_typed = typed = 0
    open_: list[bool] = []
    previous: TokenType | None = None
    for token in tokens:
        kind = token.token_type
        if kind in _OPENING:
            after_type = previous in type_tokens
            open_.append(after_type)
            typed += after_type
            deepest, deepest_typed = max(deepest, len(open_)), max(deepest_typed, typed)
        elif kind in _CLOSING and open_:
            typed -= open_.pop()
        previous = kind
    return deepest, deepest_typed


class ParseCheck:
    """Reads the SQL once, for every check after it. It first makes sure reading it is safe:
    sqlglot's parser goes back and tries again when a guess was wrong, and a query built
    for it can make that take hours."""

    name = "parse"

    def run(self, ctx: CheckContext) -> Refusal | None:
        if len(ctx.sql) > MAX_LENGTH:
            return Refusal(
                RefusalCode.QUERY_TOO_COMPLEX,
                f"the query is {len(ctx.sql):,} characters long; at most {MAX_LENGTH:,} are read",
            )
        if "\x00" in ctx.sql or not _is_text(ctx.sql):
            return Refusal(
                RefusalCode.PARSE_ERROR,
                "the query contains a NUL character or half a surrogate pair, which no "
                "database takes as text",
            )
        dialect = Dialect.get_or_raise(ctx.dialect)
        try:
            tokens = dialect.tokenize(ctx.sql)
        except TokenError:
            return Refusal(
                RefusalCode.PARSE_ERROR,
                "the query ends inside a string, a quoted name or a comment: one of them "
                "is never closed",
            )
        deepest, deepest_typed = nesting(tokens, dialect.parser_class.TYPE_TOKENS)
        if deepest > MAX_NESTING:
            return Refusal(
                RefusalCode.QUERY_TOO_COMPLEX,
                f"brackets nest {deepest} deep in the query; at most {MAX_NESTING} levels are read",
            )
        if deepest_typed > MAX_TYPE_NESTING:
            return Refusal(
                RefusalCode.QUERY_TOO_COMPLEX,
                f"the query nests {deepest_typed} type names with brackets, like "
                f"date(date(...)) or array[array[...]]; at most {MAX_TYPE_NESTING} levels "
                "are read",
            )
        try:
            parsed = dialect.parser().parse(tokens, ctx.sql)
            ctx.statements = [statement for statement in parsed if statement is not None]
            if len(ctx.statements) == 1:
                # Writing it back out is what the query ends in if it is allowed. Done once
                # here, so a tree too deep to write is refused now and not after the checks.
                ctx.sql_to_run()
        except ParseError as exc:
            return Refusal(RefusalCode.PARSE_ERROR, describe_parse_error(exc))
        except RecursionError:
            return Refusal(
                RefusalCode.QUERY_TOO_COMPLEX,
                "the query nests too deeply to be read; simplify it",
            )
        if not ctx.statements:
            return Refusal(RefusalCode.PARSE_ERROR, "the query is empty")
        return None
