"""Table and column access: a query may read only what the active profile allows.

Names are resolved the way the database resolves them: against every table the role can read
(the catalog), innermost scope first, then the profile's rules are applied to what they resolve
to. Resolving against only the allowed columns would be wrong: in a correlated subquery an
unqualified name the profile may not read in the inner table would look like the outer one's.

What runs is the query as written, with each table pinned to its schema, so the database can't
pick a different table than the one checked (through search_path, say). It is not the qualified
tree used for checking: qualifying renames outputs and rewrites JOIN ... USING.
"""

from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import Scope, traverse_scope

from sql_warden.catalog import Catalog
from sql_warden.config import EVERYTHING
from sql_warden.engines import EngineError
from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline.base import CheckContext
from sql_warden.profiles import Access

DEFAULT_SCHEMAS = {"postgres": "public", "snowflake": "PUBLIC"}
"""Where an unqualified table name is looked up, per dialect, unless the Warden is told
another: the name as the database stores it, which in Snowflake is upper case."""
_ALIAS_CLAUSES = (exp.Order, exp.Group, exp.Having, exp.Distinct)
"""Clauses where a bare name may be an output column of the same SELECT (DISTINCT ON follows
the ORDER BY rules)."""


class _Refused(Exception):
    def __init__(self, code: RefusalCode, reason: str) -> None:
        super().__init__(reason)
        self.refusal = Refusal(code, reason)


def _is_table(source: object) -> bool:
    """A real table, as opposed to a CTE, a derived table or a table function."""
    return isinstance(source, exp.Table) and isinstance(source.this, exp.Identifier)


def _resolve(scope: Scope, alias: str) -> exp.Expr | Scope | None:
    """What alias names in scope: its own sources first, then enclosing ones (correlation)."""
    current: Scope | None = scope
    while current is not None:
        if alias in current.sources:
            source: exp.Expr | Scope = current.sources[alias]
            return source
        current = current.parent
    return None


def _clause_in_scope(node: exp.Expr, scope: Scope) -> exp.Expr | None:
    """The ORDER BY, GROUP BY or HAVING of this scope that node sits in, if any."""
    current = node.parent
    while current is not None and current is not scope.expression:
        if isinstance(current, _ALIAS_CLAUSES):
            return current
        current = current.parent
    return None


def _output_names(scope: Scope) -> set[str]:
    expression = scope.expression
    while isinstance(expression, exp.SetOperation):  # a UNION's columns are its first branch's
        expression = expression.left
    if isinstance(expression, exp.Select):
        return {select.alias_or_name for select in expression.selects}
    return set()


def _table_name(table: exp.Table) -> str:
    return f"{table.db}.{table.name}"


def _real_tables(tree: exp.Expr) -> list[tuple[str, str]]:
    return sorted(
        (source.db, source.name)
        for scope in traverse_scope(tree)
        for source in scope.sources.values()
        if isinstance(source, exp.Table) and _is_table(source)
    )


class AccessCheck:
    """Refuses tables, columns and stars the profile may not read."""

    name = "access"

    def __init__(
        self,
        catalog: Catalog,
        access: Access,
        *,
        profile: str,
        dialect: str = "postgres",
        default_schema: str | None = None,
    ) -> None:
        self._catalog = catalog
        self._access = access
        self._profile = profile
        self._dialect = dialect
        self._default_schema = default_schema or DEFAULT_SCHEMAS[dialect]

    def run(self, ctx: CheckContext) -> Refusal | None:
        try:
            schema = self._catalog.schema()
        except EngineError as exc:
            return Refusal(
                RefusalCode.CATALOG_UNAVAILABLE,
                f"could not read the tables and columns to check access: {exc}",
            )
        tree = ctx.statements[0]
        try:
            for join in tree.find_all(exp.Join):
                # Checked on the query as written: qualifying would turn it into a plain join.
                if join.method == "NATURAL":
                    raise _Refused(
                        RefusalCode.COLUMN_NOT_ALLOWED,
                        "NATURAL JOIN compares columns it doesn't name; join with ON or USING",
                    )
            for table in tree.find_all(exp.Table):
                alias = table.args.get("alias")
                if _is_table(table) and alias is not None and alias.columns:
                    # `products x(a, b, name)` renames by position: x.name would be category.
                    raise _Refused(
                        RefusalCode.COLUMN_NOT_ALLOWED,
                        f"{table.sql(dialect=self._dialect)} renames the table's columns; "
                        "alias them in the SELECT instead",
                    )
            self._pin_schemas(tree)
            checked = qualify(
                tree.copy(),
                schema=schema,
                dialect=self._dialect,
                db=self._default_schema,
                expand_stars=False,
                validate_qualify_columns=False,
            )
            if _real_tables(checked) != _real_tables(tree):
                # What runs must read exactly the tables that were checked.
                raise _Refused(
                    RefusalCode.TABLE_NOT_ALLOWED,
                    "could not work out which tables the query reads; name them as schema.table",
                )
            for scope in traverse_scope(checked):
                self._check_scope(scope)
        except _Refused as refused:
            return refused.refusal
        except SqlglotError as exc:
            return Refusal(
                RefusalCode.COLUMN_NOT_ALLOWED, f"could not resolve the query's columns: {exc}"
            )
        return None

    def _pin_schemas(self, tree: exp.Expr) -> None:
        # Fold unquoted names first, as the database does, so a CTE written WITH X is found as
        # x here too rather than taken for a table.
        normalize_identifiers(tree, dialect=self._dialect)
        for scope in traverse_scope(tree):
            for source in scope.sources.values():
                if isinstance(source, exp.Table) and _is_table(source) and not source.db:
                    source.set("db", exp.to_identifier(self._default_schema))

    def _check_scope(self, scope: Scope) -> None:
        for table in scope.tables:
            if table.args.get("catalog"):
                raise _Refused(
                    RefusalCode.TABLE_NOT_ALLOWED,
                    f"{table.sql(dialect=self._dialect)} names a database; use schema.table",
                )
        for source in scope.sources.values():
            if isinstance(source, exp.Table) and _is_table(source):
                self._check_table(source)
        outputs = _output_names(scope)
        for node in scope.walk():
            if isinstance(node, exp.Star) and not isinstance(node.parent, exp.Column):
                # SELECT *, and * handed to a function, which reads every column just the
                # same: OBJECT_CONSTRUCT(*). Only COUNT(*) reads none of them.
                if isinstance(node.parent, exp.Count):
                    continue
                for _, source in scope.selected_sources.values():
                    if isinstance(source, exp.Table) and _is_table(source):
                        self._check_star(source, "*")
            elif isinstance(node, exp.TableColumn):
                # A table alias used as a value, `SELECT p FROM products p`: the whole row.
                row = self._source(scope, node.name)
                if isinstance(row, exp.Table) and _is_table(row):
                    self._check_star(row, node.name)
            elif isinstance(node, exp.Column):
                self._check_column(scope, node, outputs)

    def _check_column(self, scope: Scope, column: exp.Column, outputs: set[str]) -> None:
        if isinstance(column.this, exp.Star):
            source = self._source(scope, column.table)
            if isinstance(source, exp.Table) and _is_table(source):
                self._check_star(source, f"{column.table}.*")
            return
        if not column.table:
            whole_row = _resolve(scope, column.name)
            if whole_row is not None:  # `SELECT p FROM products p` reads every column
                if isinstance(whole_row, exp.Table) and _is_table(whole_row):
                    self._check_star(whole_row, column.name)
                return
            if column.name in outputs and _clause_in_scope(column, scope) is not None:
                return  # ORDER BY, GROUP BY, HAVING, DISTINCT ON an output column: checked
            # Left unqualified by sqlglot (it doesn't qualify DISTINCT ON, say): exactly one
            # of this scope's sources must have it, as for the database; else it's refused.
            table = self._only_source_with(scope, column.name)
            if table is None:
                raise self._column_refused(column.name)
            self._check_table_column(table, column.name)
            return
        source = self._source(scope, column.table)
        if isinstance(source, exp.Table) and _is_table(source):
            self._check_table_column(source, column.name)

    def _only_source_with(self, scope: Scope, name: str) -> exp.Table | None:
        """The one real table among scope's sources that has a column called name, if there is
        exactly one and no other kind of source (a CTE, subquery or function) could have it."""
        found: list[exp.Table] = []
        for _, source in scope.selected_sources.values():
            if not (isinstance(source, exp.Table) and _is_table(source)):
                return None  # its columns aren't in the catalog: can't rule it out
            table = self._catalog.table(source.db, source.name)
            if table is not None and any(c.name == name for c in table.columns):
                found.append(source)
        return found[0] if len(found) == 1 else None

    def _check_table_column(self, source: exp.Table, name: str) -> None:
        allowed = self._access.columns(source.db, source.name)
        table = self._catalog.table(source.db, source.name)
        exists = table is not None and any(c.name == name for c in table.columns)
        if not exists or (allowed != EVERYTHING and name not in (allowed or ())):
            raise self._column_refused(name)

    def _source(self, scope: Scope, alias: str) -> exp.Expr | Scope:
        source = _resolve(scope, alias)
        if source is None:
            raise _Refused(
                RefusalCode.COLUMN_NOT_ALLOWED,
                f"{alias} is not a table this query reads, or not one profile "
                f"{self._profile} may read",
            )
        return source

    def _check_table(self, table: exp.Table) -> None:
        allowed = self._access.columns(table.db, table.name)
        if allowed is None or self._catalog.table(table.db, table.name) is None:
            # The same answer for a table that doesn't exist: a profile can't probe for names.
            raise _Refused(
                RefusalCode.TABLE_NOT_ALLOWED,
                f"table {_table_name(table)} is not available to profile {self._profile}",
            )

    def _check_star(self, table: exp.Table, written: str) -> None:
        allowed = self._access.columns(table.db, table.name)
        if allowed == EVERYTHING:
            return
        listed = ", ".join(sorted(allowed or ()))
        raise _Refused(
            RefusalCode.STAR_NOT_ALLOWED,
            f"{written} reads every column of {_table_name(table)}, but profile "
            f"{self._profile} may read only {listed}; list the columns instead",
        )

    def _column_refused(self, name: str) -> _Refused:
        # The same answer for a column that doesn't exist and one the profile may not read.
        return _Refused(
            RefusalCode.COLUMN_NOT_ALLOWED,
            f"column {name} is not available to profile {self._profile}",
        )
