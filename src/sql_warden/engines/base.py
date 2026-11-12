"""What sql-warden needs from a database, independent of which database it is."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Result:
    columns: tuple[str, ...]
    rows: tuple[tuple[object, ...], ...]
    truncated: bool
    """True when the query produced more rows than the engine's row cap."""
    duration_ms: float


@dataclass(frozen=True)
class Column:
    name: str
    type: str


@dataclass(frozen=True)
class Table:
    schema: str
    name: str
    columns: tuple[Column, ...]


@dataclass(frozen=True)
class CostEstimate:
    """What the database's planner expects a query to cost. Getting one runs nothing."""

    total_cost: float
    """The planner's estimate for the whole query, in the database's own units. Postgres:
    abstract cost units, in which reading one page from disk in sequence costs 1.0.
    Snowflake: the bytes in the micro-partitions the query may scan."""
    est_rows: int | None
    """The rows the planner expects the query to return. None where it doesn't say
    (Snowflake)."""
    top_node: str
    """The step of the plan that adds the most cost of its own, e.g. "Seq Scan on orders"."""
    unit: str | None = None
    """What total_cost counts, where that has a name: "bytes" for Snowflake. None for
    Postgres, whose units are only the planner's."""
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)
    """The plan, as the database gave it."""


class EngineError(Exception):
    """A query could not be run. The message is safe to show to the caller."""


class EngineUnavailable(EngineError):
    """The database could not be reached."""


class QueryTimeout(EngineError):
    """The query ran past the engine's statement timeout and was cancelled."""


class QueryFailed(EngineError):
    """The database rejected or failed the query."""

    def __init__(self, message: str, sqlstate: str | None = None) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


class Engine(Protocol):
    max_rows: int
    """The row cap: execute() returns at most this many rows."""

    def execute(self, sql: str, *, tag: str | None = None) -> Result:
        """Run one read-only query, returning at most the engine's row cap.

        tag names the request (its audit id) to the database, where the database has
        somewhere to put it: Snowflake's QUERY_TAG, which its query history shows."""
        ...

    def tables(self) -> tuple[Table, ...]:
        """The tables and views the engine's role can read, with their columns."""
        ...

    def explain(self, sql: str, *, tag: str | None = None) -> CostEstimate:
        """The planner's estimate for one read-only query, without running it."""
        ...
