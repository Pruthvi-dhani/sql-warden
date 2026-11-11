"""Where a query's masked columns go: into which outputs, and into which other uses.

A masked column is safe in exactly one shape: selected as it is, so each value reaches the
caller through the column's own mask. That survives aliases, CTEs, subqueries and a UNION ALL
of the same column. Every other appearance is a use that can give the values away:

- outside a select list (WHERE, JOIN, GROUP BY, HAVING, ORDER BY, DISTINCT, a window, a set
  operation that compares rows): which rows come back, how many and in what order depends on
  the hidden values. `WHERE ssn LIKE '123%'` reads an SSN one digit at a time.
- inside an expression: `'xxxx' || substr(ssn, 1, 4)` walks the value past a partial mask,
  `ssn LIKE '123%'` is one bit per row under any mask that tells values apart, and even a
  fully hidden result can signal through an error (`1 / (CASE WHEN ... THEN 0 ...)`).

COUNT(column) and COUNT(DISTINCT column) say how many values there are, not what they are, and
are not uses.

The analysis runs on a copy of the query with every name resolved and every star expanded. It
is conservative: what it can't follow counts as derived from every masked column in reach, or
stops the query (LineageError).
"""

from collections.abc import Collection, Iterator
from dataclasses import dataclass
from typing import Literal, TypeGuard

from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import Scope, ScopeType, traverse_scope
from sqlglot.schema import Schema

MaskedColumn = tuple[str, str, str]
"""schema, table, column: exact names, as the database stores them."""

_CLAUSES = {
    "where": "WHERE",
    "joins": "JOIN",
    "from_": "FROM",
    "from": "FROM",
    "group": "GROUP BY",
    "having": "HAVING",
    "order": "ORDER BY",
    "qualify": "QUALIFY",
    "windows": "WINDOW",
    "distinct": "DISTINCT ON",
    "limit": "LIMIT",
    "offset": "OFFSET",
}
_MAX_PASSES = 25
_SNIPPET = 60


class LineageError(Exception):
    """The query's columns could not be followed, so nothing can be said about its outputs."""


@dataclass(frozen=True)
class Flow:
    """What a value carries of the masked columns."""

    columns: frozenset[MaskedColumn] = frozenset()
    """The masked columns it comes from. Empty: none, and it can be shown as it is."""
    unchanged: bool = True
    """True if it is one masked column's values exactly, so that column's mask applies. False
    if it was computed or mixed from them: only hiding it entirely is safe."""

    def __post_init__(self) -> None:
        if self.unchanged and len(self.columns) > 1:
            raise ValueError("a value can be only one column unchanged")


CLEAR = Flow()


def _derived(columns: Collection[MaskedColumn]) -> Flow:
    return Flow(frozenset(columns), unchanged=False) if columns else CLEAR


def _mixed(flows: Collection[Flow]) -> Flow:
    """Values that may be any of flows: the rows of a UNION ALL, say."""
    distinct = set(flows)
    if len(distinct) == 1:
        return next(iter(distinct))
    return _derived({column for flow in distinct for column in flow.columns})


@dataclass(frozen=True)
class Output:
    """One column of the query's result, by position."""

    name: str
    flow: Flow


@dataclass(frozen=True)
class Use:
    """A masked column used where its values could leak."""

    column: MaskedColumn
    kind: Literal["predicate", "expression"]
    where: str
    """The clause (WHERE, ORDER BY, ...) or the expression, for the refusal's reason."""


@dataclass(frozen=True)
class Lineage:
    outputs: tuple[Output, ...]
    """The result's columns, in order. Empty if the query reads no masked column at all."""
    uses: tuple[Use, ...]

    @property
    def masked(self) -> bool:
        return any(output.flow.columns for output in self.outputs)


NOTHING = Lineage((), ())


@dataclass(frozen=True)
class _Opaque:
    """A source whose columns can't be told apart (a table function, UNNEST): each of them
    counts as derived from everything masked that went into it."""

    columns: frozenset[MaskedColumn]


def trace(
    tree: exp.Expr,
    masked: Collection[MaskedColumn],
    *,
    schema: Schema,
    dialect: str = "postgres",
    default_schema: str = "public",
) -> Lineage:
    """Follow the masked columns through tree, a query the earlier checks approved.

    schema is every table the role can read, so stars and bare column names resolve as the
    database resolves them. tree is not changed."""
    if not masked:
        return NOTHING
    try:
        qualified = qualify(
            tree.copy(),
            schema=schema,
            dialect=dialect,
            db=default_schema,
            expand_stars=True,
            validate_qualify_columns=False,
        )
        scopes = traverse_scope(qualified)
    except SqlglotError as exc:
        raise LineageError(f"could not resolve the query's columns: {exc}") from exc
    if not scopes:
        raise LineageError("could not work out what the query reads")
    tables = {
        (source.db, source.name)
        for scope in scopes
        for source in scope.sources.values()
        if _is_table(source)
    }
    if not any((schema_, table) in tables for schema_, table, _ in masked):
        return NOTHING  # no masked column's table is read: nothing to follow
    return _Tracer(scopes, frozenset(masked), dialect).run()


def _is_table(source: object) -> TypeGuard[exp.Table]:
    """A real table, as opposed to a CTE, a derived table or a table function."""
    return isinstance(source, exp.Table) and isinstance(source.this, exp.Identifier)


def _unwrap(node: exp.Expr) -> exp.Expr:
    while isinstance(node, exp.Alias | exp.Paren):
        node = node.this
    return node


def _counted(column: exp.Expr) -> bool:
    """True for the column in COUNT(column) or COUNT(DISTINCT column)."""
    parent = column.parent
    if isinstance(parent, exp.Distinct):
        parent = parent.parent
    return isinstance(parent, exp.Count)


class _Tracer:
    def __init__(self, scopes: list[Scope], masked: frozenset[MaskedColumn], dialect: str) -> None:
        self._scopes = scopes  # innermost first, the whole query last
        self._masked = masked
        self._dialect = dialect
        self._by_root = {id(scope.expression): scope for scope in scopes}
        # By each scope's query, not the scope: a recursive CTE's reference to itself is
        # another Scope object over the same query.
        self._outputs: dict[int, list[Output] | _Opaque] = {}
        self._uses: list[Use] = []
        self._strict = False

    def run(self) -> Lineage:
        # To a fixed point, for recursive CTEs: a scope can read its own outputs.
        for _ in range(_MAX_PASSES):
            before = dict(self._outputs)
            self._pass()
            if self._outputs == before:
                break
        else:
            raise LineageError("could not follow the query's columns: too deeply recursive")
        self._strict = True  # every source is known now: an unknown one is an error
        self._uses = []
        self._pass()
        outputs = self._outputs[id(self._scopes[-1].expression)]
        if isinstance(outputs, _Opaque):
            raise LineageError("could not work out the columns the query returns")
        return Lineage(tuple(outputs), tuple(dict.fromkeys(self._uses)))

    def _pass(self) -> None:
        for scope in self._scopes:
            self._outputs[id(scope.expression)] = self._scope_outputs(scope)

    # ------------------------------------------------------------ one scope's outputs

    def _scope_outputs(self, scope: Scope) -> list[Output] | _Opaque:
        expression = scope.expression
        if isinstance(expression, exp.Select):
            return self._select_outputs(scope, expression)
        if isinstance(expression, exp.SetOperation):
            return self._set_operation_outputs(scope, expression)
        if isinstance(expression, exp.Lateral) and isinstance(expression.this, exp.Subquery):
            inner = self._by_root.get(id(expression.this.unnest()))
            if inner is not None:  # LATERAL (SELECT ...): its columns are the subquery's
                return self._outputs.get(id(inner.expression), [])
        # A table function, UNNEST, VALUES: what goes in decides how many rows come out, so
        # anything masked among it is a use, and every column it returns is derived from it.
        columns = self._columns_within(scope, expression)
        self._uses += [Use(column, "predicate", "FROM") for column in sorted(columns)]
        return _Opaque(columns)

    def _select_outputs(self, scope: Scope, select: exp.Select) -> list[Output]:
        outputs = []
        for item in select.selects:
            inner = _unwrap(item)
            if isinstance(inner, exp.Star) or (
                isinstance(inner, exp.Column) and isinstance(inner.this, exp.Star)
            ):
                raise LineageError(
                    f"could not tell which columns {inner.sql(dialect=self._dialect)} returns "
                    "here; list them"
                )
            if isinstance(inner, exp.Column) and inner.table:
                flow = self._column_flow(scope, inner)  # a column as it is
            else:
                flow = _derived(self._columns_within(scope, inner))
                self._uses += [
                    Use(column, "expression", self._snippet(inner))
                    for column in sorted(flow.columns)
                ]
            outputs.append(Output(item.alias_or_name, flow))

        for key, clause in select.args.items():
            if key in ("expressions", "with", "with_") or clause is None:
                continue
            for node in clause if isinstance(clause, list) else [clause]:
                if isinstance(node, exp.Expr):
                    columns = self._columns_within(scope, node, outputs)
                    where = _CLAUSES.get(key, key.upper())
                    self._uses += [Use(column, "predicate", where) for column in sorted(columns)]
        if select.args.get("distinct") is not None:
            # DISTINCT compares whole rows: one row or two says whether values were equal.
            self._uses += [
                Use(column, "predicate", "DISTINCT")
                for output in outputs
                for column in sorted(output.flow.columns)
            ]
        return outputs

    def _set_operation_outputs(self, scope: Scope, operation: exp.SetOperation) -> list[Output]:
        branches = []
        for side in (operation.left, operation.right):
            branch = self._by_root.get(id(side.unnest()))
            outputs = None if branch is None else self._outputs.get(id(branch.expression))
            if not isinstance(outputs, list):
                if self._strict:
                    raise LineageError("could not follow the branches of a set operation")
                outputs = []
            branches.append(outputs)
        left, right = branches
        if left and right and len(left) != len(right):
            raise LineageError("the branches of a set operation return different columns")
        keeps_every_row = (
            isinstance(operation, exp.Union) and operation.args.get("distinct") is False
        )
        combined = [
            Output(name.name, _mixed([flow for flow in flows if flow is not None]))
            for name, *flows in _zip_outputs(left, right)
        ]
        if not keeps_every_row:
            # UNION, INTERSECT and EXCEPT compare rows: `... INTERSECT SELECT '123-45-6789'`
            # says whether that value is there.
            where = operation.key.upper()
            self._uses += [
                Use(column, "predicate", where)
                for output in combined
                for column in sorted(output.flow.columns)
            ]
        for key, clause in operation.args.items():
            if key in ("this", "expression", "with", "with_") or clause is None:
                continue
            for node in clause if isinstance(clause, list) else [clause]:
                if isinstance(node, exp.Expr):
                    columns = self._columns_within(scope, node, combined)
                    where = _CLAUSES.get(key, key.upper())
                    self._uses += [Use(column, "predicate", where) for column in sorted(columns)]
        return combined

    # ------------------------------------------------------------ what a node reads

    def _columns_within(
        self, scope: Scope, node: exp.Expr, outputs: list[Output] | None = None
    ) -> frozenset[MaskedColumn]:
        """Every masked column the expression at node depends on, COUNTs aside. outputs are
        the scope's own, for the clauses where a bare name can mean one of them (ORDER BY)."""
        found: set[MaskedColumn] = set()
        for part in self._parts(node):
            if isinstance(part, Scope):
                # A subquery used as a value or in a condition: whatever it returns.
                returned = self._outputs.get(id(part.expression), [])
                if isinstance(returned, _Opaque):
                    found |= returned.columns
                else:
                    found |= {column for output in returned for column in output.flow.columns}
            elif isinstance(part, exp.Star):
                found |= self._all_rows(scope)
            elif isinstance(part, exp.TableColumn):
                found |= self._whole_row(scope, part.name)
            elif isinstance(part, exp.Column) and not _counted(part):
                found |= self._column_flow(scope, part, outputs).columns
        return frozenset(found)

    def _parts(self, node: exp.Expr, *, start: bool = True) -> Iterator[exp.Expr | Scope]:
        """The columns, stars and subqueries under node, without going into other scopes."""
        nested = None if start else self._by_root.get(id(node))
        if nested is not None:
            if nested.scope_type is ScopeType.SUBQUERY and not self._in_exists(node):
                yield nested
            return  # a scope of its own: followed there
        if isinstance(node, exp.Column | exp.TableColumn):
            yield node
            return
        if isinstance(node, exp.Star):
            if not isinstance(node.parent, exp.Count):  # COUNT(*) reads no column
                yield node
            return
        for child in node.iter_expressions():
            yield from self._parts(child, start=False)

    @staticmethod
    def _in_exists(node: exp.Expr) -> bool:
        # EXISTS asks only whether there are rows: what the subquery selects doesn't matter.
        parent = node.parent
        if isinstance(parent, exp.Subquery):
            parent = parent.parent
        return isinstance(parent, exp.Exists)

    def _column_flow(
        self, scope: Scope, column: exp.Column, outputs: list[Output] | None = None
    ) -> Flow:
        if isinstance(column.this, exp.Star):  # alias.* inside an expression: the whole row
            return _derived(self._whole_row(scope, column.table))
        if column.table:
            source = _resolve(scope, column.table)
            if source is None:
                raise LineageError(f"could not tell where {column.table}.{column.name} comes from")
            return self._source_flow(source, column.name)
        if _resolve(scope, column.name) is not None:  # a table alias used as a value
            return _derived(self._whole_row(scope, column.name))
        # A bare name. It may be one of the scope's own outputs (ORDER BY alias) or a column
        # of any of its sources: everything it could be.
        flows = [output.flow for output in outputs or [] if output.name == column.name]
        current: Scope | None = scope
        while current is not None:
            flows += [self._source_flow(source, column.name) for source in current.sources.values()]
            current = current.parent
        columns = {masked for flow in flows for masked in flow.columns}
        if len({flow for flow in flows if flow.columns}) == 1 and all(
            flow.unchanged for flow in flows if flow.columns
        ):
            return Flow(frozenset(columns), unchanged=True)
        return _derived(columns)

    def _source_flow(self, source: exp.Expr | Scope, name: str) -> Flow:
        """The flow of column name of one source: a table, or another scope's output."""
        if isinstance(source, Scope):
            outputs = self._outputs.get(id(source.expression))
            if outputs is None:
                if self._strict:
                    raise LineageError(f"could not tell where column {name} comes from")
                return CLEAR  # not followed yet: the next pass will have it
            if isinstance(outputs, _Opaque):
                return _derived(outputs.columns)
            return _mixed([o.flow for o in outputs if o.name == name]) if outputs else CLEAR
        if _is_table(source):
            column = (source.db, source.name, name)
            return Flow(frozenset({column})) if column in self._masked else CLEAR
        return CLEAR  # a table function listed as a table: handled as its own scope

    def _whole_row(self, scope: Scope, alias: str) -> frozenset[MaskedColumn]:
        """Every masked column of the source called alias: `SELECT c FROM customers c`."""
        source = _resolve(scope, alias)
        if source is None:
            raise LineageError(f"could not tell what {alias} refers to")
        return self._source_columns(source)

    def _all_rows(self, scope: Scope) -> frozenset[MaskedColumn]:
        return frozenset(
            column for source in scope.sources.values() for column in self._source_columns(source)
        )

    def _source_columns(self, source: exp.Expr | Scope) -> frozenset[MaskedColumn]:
        if isinstance(source, Scope):
            outputs = self._outputs.get(id(source.expression), [])
            if isinstance(outputs, _Opaque):
                return outputs.columns
            return frozenset(column for output in outputs for column in output.flow.columns)
        if _is_table(source):
            return frozenset(
                column for column in self._masked if column[:2] == (source.db, source.name)
            )
        return frozenset()

    def _snippet(self, node: exp.Expr) -> str:
        # Resolving the names quoted them all: unquoted reads as the query was written.
        text = " ".join(node.sql(dialect=self._dialect).replace('"', "").split())
        return text if len(text) <= _SNIPPET else text[: _SNIPPET - 1] + "…"


def _zip_outputs(
    left: list[Output], right: list[Output]
) -> Iterator[tuple[Output, Flow | None, Flow | None]]:
    """The outputs of a set operation's branches by position; names are the left's."""
    for index in range(max(len(left), len(right))):
        first = left[index] if index < len(left) else None
        second = right[index] if index < len(right) else None
        named = first or second
        assert named is not None
        yield named, None if first is None else first.flow, None if second is None else second.flow


def _resolve(scope: Scope, alias: str) -> exp.Expr | Scope | None:
    """What alias names in scope: its own sources first, then enclosing ones (correlation)."""
    current: Scope | None = scope
    while current is not None:
        if alias in current.sources:
            source: exp.Expr | Scope = current.sources[alias]
            return source
        current = current.parent
    return None
