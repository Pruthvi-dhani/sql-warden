"""What sql-warden needs from a database, independent of which database it is."""

from dataclasses import dataclass
from typing import Protocol


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

    def execute(self, sql: str) -> Result:
        """Run one read-only query, returning at most the engine's row cap."""
        ...

    def tables(self) -> tuple[Table, ...]:
        """The tables and views the engine's role can read, with their columns."""
        ...
