"""What a server finds out about its database role before it serves anything with it.

The checks decide what an agent may run. The role is what holds if they are wrong: a role
that can't write can't be made to, whatever gets past them. So a server looks first, and
doesn't start as a role that can change the database. It also says when the role can read
more than its profile allows: then only the access check stands between the two.
"""

from collections.abc import Iterable
from dataclasses import dataclass

from sql_warden.config import EVERYTHING
from sql_warden.engines import Engine, RoleReport, Table
from sql_warden.profiles import Access

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

    @property
    def can_write(self) -> bool:
        return not self.report.read_only


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


def check_role(engine: Engine, access: Access | None) -> RoleCheck:
    """Ask the database what the engine's role can do. Raises EngineError if it can't be
    asked: a role nobody could look at is not one to serve."""
    report = engine.role()
    if not report.read_only:
        return RoleCheck(report)  # it won't be served, so what it reads doesn't matter
    return RoleCheck(report, beyond_profile(engine.tables(), access))


def listed(findings: Iterable[str], *, prefix: str = "", shown: int = SHOWN) -> list[str]:
    """The first few findings, one a line, and how many more there are."""
    findings = list(findings)
    lines = [f"{prefix}{finding}" for finding in findings[:shown]]
    if len(findings) > shown:
        lines.append(f"and {len(findings) - shown} more")
    return lines
