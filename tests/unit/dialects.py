"""Running one test under each SQL dialect the checks read.

The check tests are written as for Postgres: lower-case names, as Postgres stores an unquoted
one. Under Snowflake the same SQL means upper-case names, so the catalog a test is given
stores them that way, and text that names things is compared without regard to case. A test
that asks for the `dialect` fixture (tests/unit/conftest.py) runs once per dialect; one marked
`postgres_only` runs under Postgres alone.
"""

from collections.abc import Iterable

from sql_warden.engines import Column, Table

DIALECTS = ("postgres", "snowflake")
_current = "postgres"  # set by the dialect fixture, for the test that is running


def current() -> str:
    return _current


def stored(name: str) -> str:
    """name as the running dialect's database stores it when it was created unquoted. A name
    that isn't all lower case was created quoted, and is stored as written everywhere."""
    return name.upper() if _current == "snowflake" and name.islower() else name


def catalog(tables: Iterable[Table]) -> tuple[Table, ...]:
    """tables, with their names as the running dialect stores them."""
    return tuple(
        Table(
            stored(table.schema),
            stored(table.name),
            tuple(Column(stored(column.name), column.type) for column in table.columns),
        )
        for table in tables
    )


def names[T: tuple[str, ...]](parts: T) -> T:
    """A (schema, table) or (schema, table, column), as stored."""
    return tuple(stored(part) for part in parts)  # type: ignore[return-value]


class Folded(str):
    """Text from the checks that is compared without regard to case: SQL and reasons name
    tables and columns, whose case is the dialect's."""

    __slots__ = ()

    def __eq__(self, other: object) -> bool:
        return isinstance(other, str) and self.lower() == other.lower()

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return hash(self.lower())

    def __contains__(self, part: object) -> bool:
        return isinstance(part, str) and part.lower() in self.lower()


def text(value: str) -> str:
    """value, to be compared as the running dialect allows."""
    return Folded(value) if _current == "snowflake" else value
