"""Structural rules: one read-only SELECT, safe functions, bounded joins, nesting and rows."""

from sqlglot import exp
from sqlglot.optimizer.scope import ScopeType, traverse_scope

from sql_warden.config import BUILTIN_DENIED_FUNCTIONS, ShapeConfig
from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline.base import CheckContext

# Scopes that are a level of nesting. Union branches and the table function wrapping a LATERAL
# subquery are not: they sit beside their parent, not inside it.
_NESTED = {ScopeType.SUBQUERY, ScopeType.DERIVED_TABLE, ScopeType.CTE}
_STATEMENT_NAMES = {"truncatetable": "TRUNCATE", "transaction": "BEGIN"}


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def _statement_name(statement: exp.Expr) -> str | None:
    if isinstance(statement, exp.Command):
        return str(statement.this).upper()
    if isinstance(statement, exp.Alias):  # what sqlglot makes of `TABLE t`, `NOTIFY x`, ...
        return None
    return _STATEMENT_NAMES.get(statement.key, statement.key.upper())


def _function_name(func: exp.Func) -> str:
    # sqlglot keeps the name only for functions it doesn't know; known ones use its own name.
    return func.name.lower() if isinstance(func, exp.Anonymous) else func.sql_name().lower()


def subquery_depth(query: exp.Query) -> int:
    deepest = 0
    for scope in traverse_scope(query.unnest()):
        depth, current = 0, scope
        while current.parent is not None:
            if current.scope_type in _NESTED:
                depth += 1
            current = current.parent
        deepest = max(deepest, depth)
    return deepest


class ShapeCheck:
    """Refuses anything but a single read-only SELECT within the configured limits.

    It also puts a LIMIT on every query, or refuses one without, as the policy says.
    """

    name = "shape"

    def __init__(self, rules: ShapeConfig, *, max_rows: int) -> None:
        self.rules = rules
        self.max_rows = max_rows

    def run(self, ctx: CheckContext) -> Refusal | None:
        if len(ctx.statements) != 1:
            return Refusal(
                RefusalCode.MULTIPLE_STATEMENTS,
                f"send one statement at a time; this query has {len(ctx.statements)}",
            )
        statement = ctx.statements[0]
        if not isinstance(statement, exp.Query):
            name = _statement_name(statement)
            return Refusal(
                RefusalCode.NOT_A_SELECT,
                f"only SELECT queries are allowed, not {name}"
                if name
                else "only SELECT queries are allowed",
            )
        return (
            self._read_only(statement, ctx.dialect)
            or self._named_outright(statement, ctx.dialect)
            or self._functions(statement, ctx.dialect)
            or self._joins(statement)
            or self._nesting(statement)
            or self._limit(statement, ctx)
        )

    def _read_only(self, query: exp.Query, dialect: str) -> Refusal | None:
        write = query.find(exp.DML)
        if write is not None:
            where = f" in the CTE {write.parent.alias}" if isinstance(write.parent, exp.CTE) else ""
            return Refusal(
                RefusalCode.NOT_READ_ONLY,
                f"the query contains a {write.key.upper()}{where}; queries must not modify data",
            )
        if query.find(exp.Into) is not None:
            return Refusal(
                RefusalCode.NOT_READ_ONLY,
                "SELECT ... INTO creates a table; queries must not modify data",
            )
        lock = query.find(exp.Lock)
        if lock is not None:
            # Some dialects have no syntax for it to print; the lock was asked for all the same.
            written = lock.sql(dialect=dialect) or "FOR UPDATE"
            return Refusal(
                RefusalCode.NOT_READ_ONLY, f"{written} locks rows; queries must not take locks"
            )
        if dialect == "snowflake":
            for column in query.find_all(exp.Column):
                if column.table and column.name.upper() == "NEXTVAL" and not column.this.quoted:
                    return Refusal(
                        RefusalCode.NOT_READ_ONLY,
                        f"{column.sql(dialect=dialect)} advances a sequence; queries must not "
                        "modify data",
                    )
        return None

    def _named_outright(self, query: exp.Query, dialect: str) -> Refusal | None:
        """Everything a query reads must be named in its text, where the access and masking
        checks can see it. Snowflake has several ways around that: a name given as a string or
        a variable, a column given by its position, a stage's files."""
        if dialect != "snowflake":
            return None
        if query.find(exp.DynamicIdentifier) is not None:
            return Refusal(
                RefusalCode.FUNCTION_NOT_ALLOWED,
                "identifier() is never allowed: it names a table or column with a string or a "
                "variable, which can't be checked; write the name itself",
            )
        for wrapped in query.find_all(exp.TableFromRows):
            inner = wrapped.this
            if isinstance(inner, exp.Dot):  # information_schema.some_function()
                inner = inner.expression
            if not isinstance(inner, exp.Func):
                return Refusal(
                    RefusalCode.FUNCTION_NOT_ALLOWED,
                    f"{wrapped.sql(dialect=dialect)} names a table with a string or a "
                    "variable, which can't be checked; write the table's name itself",
                )
        for table in query.find_all(exp.Table):
            if not isinstance(table.this, exp.Identifier | exp.Func):
                return Refusal(
                    RefusalCode.TABLE_NOT_ALLOWED,
                    f"{table.this.sql(dialect=dialect)} is not a table: files in stages can't "
                    "be queried",
                )
        parameter = query.find(exp.Parameter)
        if parameter is not None:
            written = parameter.sql(dialect=dialect)
            return Refusal(
                RefusalCode.COLUMN_NOT_ALLOWED,
                f"{written} is a column given by its position, or a session variable; neither "
                "can be checked, so name the column or write the value",
            )
        return None

    def _functions(self, query: exp.Query, dialect: str) -> Refusal | None:
        for func in query.find_all(exp.Func):
            name = _function_name(func)
            pattern = self.rules.denied_by(name, dialect)
            if pattern in BUILTIN_DENIED_FUNCTIONS[dialect]:
                return Refusal(
                    RefusalCode.FUNCTION_NOT_ALLOWED,
                    f"{name}() is never allowed: it can act on the server, or read what the "
                    "checks can't see",
                )
            if pattern is not None:
                return Refusal(
                    RefusalCode.FUNCTION_NOT_ALLOWED,
                    f"{name}() is denied by shape.denied_functions ({pattern!r})",
                )
            if isinstance(func, exp.Anonymous) and name not in self.rules.allowed_functions:
                return Refusal(
                    RefusalCode.FUNCTION_NOT_ALLOWED,
                    f"{name}() is not a standard SQL function sql-warden knows; "
                    "it must be listed in shape.allowed_functions",
                )
        return None

    def _joins(self, query: exp.Query) -> Refusal | None:
        joins = len(list(query.find_all(exp.Join)))
        if joins <= self.rules.max_joins:
            return None
        return Refusal(
            RefusalCode.TOO_MANY_JOINS,
            f"the query has {_plural(joins, 'join')}; at most {self.rules.max_joins} "
            "are allowed (shape.max_joins)",
        )

    def _nesting(self, query: exp.Query) -> Refusal | None:
        depth = subquery_depth(query)
        if depth <= self.rules.max_subquery_depth:
            return None
        return Refusal(
            RefusalCode.SUBQUERY_TOO_DEEP,
            f"subqueries and CTEs nest {_plural(depth, 'level')} deep; at most "
            f"{self.rules.max_subquery_depth} are allowed (shape.max_subquery_depth)",
        )

    def _limit(self, query: exp.Query, ctx: CheckContext) -> Refusal | None:
        # Lowered or added LIMITs keep one row past the cap, so the engine can still tell
        # whether rows were cut off.
        cap, injected = self.max_rows, self.max_rows + 1
        clause = query.args.get("limit")
        if clause is None:
            if self.rules.limit == "require":
                return Refusal(
                    RefusalCode.LIMIT_REQUIRED,
                    f"the query has no LIMIT; add one of at most {cap} (the row cap)",
                )
            query.set("limit", exp.Limit(expression=exp.Literal.number(injected)))
            ctx.rewrites.append(f"added LIMIT {injected} (row cap {cap} + 1 to detect truncation)")
            return None

        value = _limit_value(clause, ctx.dialect)
        if isinstance(value, str):
            return Refusal(RefusalCode.INVALID_LIMIT, value)
        if self.rules.limit == "require" and value > cap:
            return Refusal(
                RefusalCode.LIMIT_TOO_HIGH, f"LIMIT {value} is above the row cap of {cap}"
            )
        if value > injected:
            query.set("limit", exp.Limit(expression=exp.Literal.number(injected)))
            ctx.rewrites.append(
                f"lowered LIMIT {value} to {injected} (row cap {cap} + 1 to detect truncation)"
            )
        return None


def _limit_value(clause: exp.Expr, dialect: str) -> int | str:
    """The row count of a LIMIT or FETCH clause, or why it has none sql-warden can enforce."""
    if isinstance(clause, exp.Fetch):
        options = clause.args.get("limit_options")
        if options is not None and options.args.get("percent"):
            return "FETCH ... PERCENT is not supported; give a row count"
        if options is not None and options.args.get("with_ties"):
            return "FETCH ... WITH TIES can return more rows than asked for; use LIMIT"
        count = clause.args.get("count")
        if count is None:
            return 1  # FETCH FIRST ROW ONLY
    else:
        count = clause.expression
    if isinstance(count, exp.Literal) and count.is_int:
        return int(count.name)
    return f"the LIMIT must be a whole number, not {count.sql(dialect=dialect)}"
