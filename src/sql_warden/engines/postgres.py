import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg import errors

from sql_warden.engines.base import (
    Column,
    CostEstimate,
    EngineUnavailable,
    QueryFailed,
    QueryTimeout,
    Result,
    Table,
)

# information_schema lists only what the connecting role has privileges on.
_TABLES_SQL = """
    SELECT c.table_schema, c.table_name, c.column_name, c.data_type
    FROM information_schema.columns c
    JOIN information_schema.tables t USING (table_schema, table_name)
    WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
      AND t.table_type IN ('BASE TABLE', 'VIEW')
    ORDER BY c.table_schema, c.table_name, c.ordinal_position
"""

_CURSOR = "sql_warden"
# psycopg runs a named cursor's query as this prefix plus the SQL, and Postgres reports error
# positions in that statement.
_DECLARE = f'DECLARE "{_CURSOR}" CURSOR FOR '
# Plain EXPLAIN plans a query without running it. Never ANALYZE: that runs it. The SQL after
# this prefix can't turn it into EXPLAIN ANALYZE either: EXPLAIN takes a statement, not
# another EXPLAIN, so "EXPLAIN (FORMAT JSON) EXPLAIN ANALYZE ..." is a syntax error.
_EXPLAIN = "EXPLAIN (FORMAT JSON) "
_CONTEXT = 40
"""Characters of SQL shown on each side of an error position."""


def point_at(sql: str, offset: int) -> list[str]:
    """The line of SQL around offset, and a caret under it."""
    start = sql.rfind("\n", 0, offset) + 1
    end = sql.find("\n", offset)
    end = len(sql) if end == -1 else end
    left, right = max(start, offset - _CONTEXT), min(end, offset + _CONTEXT)
    before = "..." if left > start else ""
    after = "..." if right < end else ""
    return [
        f"  {before}{sql[left:right]}{after}",
        "  " + " " * (len(before) + offset - left) + "^",
    ]


def describe_error(exc: psycopg.Error, sql: str | None = None, prefix: str = _DECLARE) -> str:
    """The database's message, pointing into the SQL as sent rather than into the statement
    that carried it: psycopg's DECLARE, or EXPLAIN."""
    diag = exc.diag
    if diag.message_primary is None:
        return str(exc).strip()
    lines = [diag.message_primary]
    if sql is not None and diag.statement_position is not None:
        offset = int(diag.statement_position) - 1 - len(prefix)
        if 0 <= offset <= len(sql):
            lines += point_at(sql, offset)
    if diag.message_detail:
        lines.append(f"DETAIL: {diag.message_detail}")
    if diag.message_hint:
        lines.append(f"HINT: {diag.message_hint}")
    return "\n".join(lines)


_AGGREGATES = {"Sorted": "GroupAggregate", "Hashed": "HashAggregate", "Mixed": "MixedAggregate"}


def describe_node(node: Mapping[str, Any]) -> str:
    """A plan node as EXPLAIN's text format names it, e.g. "Index Scan using orders_pkey on
    orders" or "Parallel Seq Scan on orders o"."""
    kind: str = node["Node Type"]
    name: str = _AGGREGATES.get(node.get("Strategy", ""), kind) if kind == "Aggregate" else kind
    join = node.get("Join Type")
    if join and join != "Inner":
        name = (
            f"{name} {join} Join"
            if kind == "Nested Loop"
            else name.replace(" Join", f" {join} Join")
        )
    if node.get("Partial Mode") in ("Partial", "Finalize"):
        name = f"{node['Partial Mode']} {name}"
    if node.get("Parallel Aware"):
        name = f"Parallel {name}"
    if index := node.get("Index Name"):
        name += f" on {index}" if kind == "Bitmap Index Scan" else f" using {index}"
    target = node.get("Relation Name") or node.get("CTE Name") or node.get("Function Name")
    alias = node.get("Alias")
    if target:
        name += f" on {target}" + (f" {alias}" if alias and alias != target else "")
    elif alias:  # a Subquery Scan or a Values Scan
        name += f" on {alias}"
    return name


def _nodes(node: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    yield node
    for child in node.get("Plans", ()):
        yield from _nodes(child)


def _own_cost(node: Mapping[str, Any]) -> float:
    """What a node adds on top of its inputs. Negative under a Limit, which stops early."""
    return float(node["Total Cost"]) - sum(float(c["Total Cost"]) for c in node.get("Plans", ()))


def cost_estimate(explained: Mapping[str, Any]) -> CostEstimate:
    """One statement's EXPLAIN (FORMAT JSON) output as a CostEstimate."""
    root = explained["Plan"]
    costliest = max(_nodes(root), key=_own_cost)  # the first of equals: the outermost
    return CostEstimate(
        total_cost=float(root["Total Cost"]),
        est_rows=int(root["Plan Rows"]),
        top_node=describe_node(costliest),
        raw=explained,
    )


class PostgresEngine:
    """Runs queries in a read-only transaction with a statement timeout and a row cap.

    These are defence in depth: they hold even if every check in front of them is wrong.
    """

    def __init__(
        self,
        dsn: str,
        *,
        statement_timeout_ms: int = 5_000,
        max_rows: int = 1_000,
        connect_timeout_s: int = 5,
    ) -> None:
        if statement_timeout_ms <= 0:
            raise ValueError("statement_timeout_ms must be positive")
        if max_rows <= 0:
            raise ValueError("max_rows must be positive")
        if connect_timeout_s <= 0:
            raise ValueError("connect_timeout_s must be positive")
        self._dsn = dsn
        self.statement_timeout_ms = statement_timeout_ms
        self.max_rows = max_rows
        self._connect_timeout_s = connect_timeout_s

    def execute(self, sql: str, *, tag: str | None = None) -> Result:
        # tag is for engines whose database records one per query; the audit log has it here.
        started = time.perf_counter()
        # A server-side cursor streams rows, so the row cap bounds memory too.
        # It also only accepts queries: Postgres rejects anything else in DECLARE.
        with self._read_only(sql) as conn, conn.cursor(name=_CURSOR) as cur:
            cur.execute(sql)
            fetched = cur.fetchmany(self.max_rows + 1)
            columns = tuple(col.name for col in cur.description or ())

        return Result(
            columns=columns,
            rows=tuple(tuple(row) for row in fetched[: self.max_rows]),
            truncated=len(fetched) > self.max_rows,
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def explain(self, sql: str, *, tag: str | None = None) -> CostEstimate:
        # The same read-only transaction and statement timeout as execute(): planning a
        # query with many joins can itself take a while.
        with self._read_only(sql, prefix=_EXPLAIN) as conn:
            # Prepared, so Postgres takes exactly one statement. Unprepared, a query with no
            # parameters goes over the simple protocol, which would run a second statement
            # after the EXPLAIN: "SELECT 1; DELETE ..." would plan the SELECT, then delete.
            row = conn.execute(_EXPLAIN + sql, prepare=True).fetchone()
        if row is None:  # pragma: no cover - EXPLAIN always returns its one row
            raise QueryFailed("EXPLAIN returned no plan")
        (explained,) = row[0]  # one plan: there is one statement
        return cost_estimate(explained)

    def tables(self) -> tuple[Table, ...]:
        with self._read_only() as conn:
            rows = conn.execute(_TABLES_SQL).fetchall()
        columns: dict[tuple[str, str], list[Column]] = {}
        for schema, table, column, data_type in rows:
            columns.setdefault((schema, table), []).append(Column(column, data_type))
        return tuple(Table(schema, name, tuple(cols)) for (schema, name), cols in columns.items())

    @contextmanager
    def _read_only(
        self, sql: str | None = None, *, prefix: str = _DECLARE
    ) -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
        """A connection in a read-only transaction with the statement timeout, rolled back after.

        Database errors inside the block come out as engine errors; positions in them point
        into sql, if given: the query sent after prefix (the cursor's DECLARE, or EXPLAIN).
        """
        try:
            conn = psycopg.connect(self._dsn, connect_timeout=self._connect_timeout_s)
        except psycopg.OperationalError as exc:
            raise EngineUnavailable(f"could not connect to the database: {exc}") from exc

        with conn:
            conn.read_only = True
            try:
                conn.execute(
                    "SELECT set_config('statement_timeout', %s, true)",
                    (str(self.statement_timeout_ms),),
                )
                yield conn
            except errors.QueryCanceled as exc:
                raise QueryTimeout(
                    f"query cancelled after the {self.statement_timeout_ms} ms statement timeout"
                ) from exc
            except psycopg.Error as exc:
                raise QueryFailed(describe_error(exc, sql, prefix), exc.sqlstate) from exc
            finally:
                conn.rollback()
