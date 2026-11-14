"""What a server finds out about its database role before it serves anything with it.

The checks decide what an agent may run. The role is what holds if they are wrong: a role
that can't write can't be made to, whatever gets past them. So a server looks first, and
doesn't start as a role that can change the database. It also says when the role can read
more than its profile allows: then only the access check stands between the two.

And it compares the policy with what the role sees, since the warehouse changes under it: a
table the profile allows may have been dropped, a column renamed, a grant taken away. What
the profile names but can't find is refused to callers, and safe, if not useful. A masked
column that can't be found is worse: if it was renamed, the column under its new name is
read unmasked by a profile that allows the whole table.
"""

from collections.abc import Collection, Iterable
from dataclasses import dataclass

from sql_warden.config import EVERYTHING
from sql_warden.engines import Engine, RoleReport, Table
from sql_warden.profiles import Access

MaskedColumn = tuple[str, str, str]

SHOWN = 5
"""How many findings a message lists before it counts the rest."""


@dataclass(frozen=True)
class RoleCheck:
    """A profile's database role, as the database describes it."""

    report: RoleReport
    beyond: tuple[str, ...] = ()
    """What the role can read that the profile doesn't allow, e.g. "table
    public.employee_salaries", "columns phone, ssn of public.customers". The database would
    answer a query for these: only the access check refuses it."""
    missing: tuple[str, ...] = ()
    """What the profile allows that its role can't see, in the same words: dropped, renamed,
    or never granted. Queries for it are refused."""
    unmasked: tuple[str, ...] = ()
    """The profile's masked columns its role can't see, as schema.table.column: masks that
    protect nothing."""

    @property
    def can_write(self) -> bool:
        return not self.report.read_only

    @property
    def drifted(self) -> bool:
        """True if the policy names anything the role can't see."""
        return bool(self.missing or self.unmasked)


def beyond_profile(tables: Iterable[Table], access: Access | None) -> tuple[str, ...]:
    """What a role that can read `tables` can read beyond what `access` allows. Nothing for
    a profile that allows everything its role can read (and for no profile at all)."""
    if access is None or access.tables == EVERYTHING:
        return ()
    beyond = []
    for table in tables:
        name = f"{table.schema}.{table.name}"
        allowed = access.columns(table.schema, table.name)
        if allowed is None:
            beyond.append(f"table {name}")
        elif allowed != EVERYTHING:
            extra = [column.name for column in table.columns if column.name not in allowed]
            if extra:
                noun = "column" if len(extra) == 1 else "columns"
                beyond.append(f"{noun} {', '.join(extra)} of {name}")
    return tuple(beyond)


def missing_from(tables: Iterable[Table], access: Access | None) -> tuple[str, ...]:
    """What access allows that a role that can read `tables` can't see. Names are compared
    as the database stores them, as the access check compares them."""
    if access is None or access.tables == EVERYTHING:
        return ()
    assert not isinstance(access.tables, str)
    seen = {(table.schema, table.name): table for table in tables}
    missing = []
    for (schema, name), columns in access.tables.items():
        table = seen.get((schema, name))
        if table is None:
            missing.append(f"table {schema}.{name}")
        elif columns != EVERYTHING:
            have = {column.name for column in table.columns}
            gone = sorted(columns - have)
            if gone:
                noun = "column" if len(gone) == 1 else "columns"
                missing.append(f"{noun} {', '.join(gone)} of {schema}.{name}")
    return tuple(missing)


def unmasked(tables: Iterable[Table], masks: Collection[MaskedColumn]) -> tuple[str, ...]:
    """The masked columns that a role that can read `tables` can't see."""
    seen = {(t.schema, t.name): {column.name for column in t.columns} for t in tables}
    return tuple(
        ".".join(column) for column in sorted(masks) if column[2] not in seen.get(column[:2], set())
    )


def check_role(
    engine: Engine, access: Access | None, masks: Collection[MaskedColumn] = ()
) -> RoleCheck:
    """Ask the database what the engine's role can do, and compare what it can read with
    the profile. Raises EngineError if it can't be asked: a role nobody could look at is
    not one to serve."""
    report = engine.role()
    if not report.read_only:
        return RoleCheck(report)  # it won't be served, so what it reads doesn't matter
    tables = engine.tables()
    return RoleCheck(
        report,
        beyond_profile(tables, access),
        missing=missing_from(tables, access),
        unmasked=unmasked(tables, masks),
    )


def listed(findings: Iterable[str], *, prefix: str = "", shown: int = SHOWN) -> list[str]:
    """The first few findings, one a line, and how many more there are."""
    findings = list(findings)
    lines = [f"{prefix}{finding}" for finding in findings[:shown]]
    if len(findings) > shown:
        lines.append(f"and {len(findings) - shown} more")
    return lines
