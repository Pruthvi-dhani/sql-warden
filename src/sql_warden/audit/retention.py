"""Removing old audit records: `sql-warden audit prune`, run on a schedule by a role that may
remove them (sql_warden_pruner in deploy/audit_roles.sql), never by the server's own.

Everything one prune removes, and the row in audit_prunes that says so, is one transaction:
either all of it happens and is on record, or none of it does.
"""

import datetime
import re
from dataclasses import dataclass
from typing import Any

import psycopg

from sql_warden.audit.sink import AuditError
from sql_warden.config import MAX_WINDOW_HOURS

MIN_AGE = datetime.timedelta(days=1)
"""The youngest records a prune may remove: a slip of the finger shouldn't empty the log."""
_AGE = re.compile(r"\s*(\d+)\s*([dh])\s*")

_CUTOFFS = """
    SELECT now() - make_interval(secs => %(age_s)s),
           least(now() - make_interval(secs => %(age_s)s),
                 now() - make_interval(hours => %(window_h)s))
"""
# What goes: events recorded before the cutoff; the budget rows of sessions idle since it
# (a session's budget then starts again from what audit_events still has: nothing); and a
# caller's charges once older than both the cutoff and the longest window a budget can
# have, so no caller's budget gets any back.
_TARGETS = (
    ("events", "audit_events", "ts < %(cutoff)s"),
    ("sessions", "session_usage", "updated_at < %(cutoff)s"),
    ("caller_charges", "caller_charges", "ts < %(charges_cutoff)s"),
)
_RECORD = """
    INSERT INTO audit_prunes (older_than, events, sessions, caller_charges)
    VALUES (%(cutoff)s, %(events)s, %(sessions)s, %(caller_charges)s)
"""


@dataclass(frozen=True)
class Pruned:
    older_than: datetime.datetime
    """Records from before this were removed (or, for a dry run, would be)."""
    events: int
    sessions: int
    caller_charges: int
    dry_run: bool = False


def parse_age(text: str) -> datetime.timedelta:
    """`90d` or `36h`: how old a record must be to be removed. At least MIN_AGE."""
    match = _AGE.fullmatch(text)
    if match is None:
        raise ValueError(f"'{text}' is not an age: give days or hours, like 90d or 36h")
    number, unit = int(match[1]), match[2]
    age = datetime.timedelta(days=number) if unit == "d" else datetime.timedelta(hours=number)
    if age < MIN_AGE:
        raise ValueError("records younger than a day are never pruned: give 1d or more")
    return age


def prune(
    dsn: str,
    older_than: datetime.timedelta,
    *,
    dry_run: bool = False,
    connect_timeout_s: int = 5,
) -> Pruned:
    """Remove what is older than older_than, by the database's clock, and record that it
    was. A dry run counts what would go and changes nothing."""
    if older_than < MIN_AGE:
        raise ValueError("records younger than a day are never pruned")
    params: dict[str, Any] = {
        "age_s": older_than.total_seconds(),
        "window_h": MAX_WINDOW_HOURS,
    }
    try:
        with psycopg.connect(dsn, connect_timeout=connect_timeout_s) as conn:
            row = conn.execute(_CUTOFFS, params).fetchone()
            assert row is not None
            params["cutoff"], params["charges_cutoff"] = row
            for name, table, condition in _TARGETS:
                if dry_run:
                    query = f"SELECT count(*) FROM {table} WHERE {condition}"
                    counted = conn.execute(query, params).fetchone()
                    params[name] = int(counted[0]) if counted else 0
                else:
                    params[name] = conn.execute(
                        f"DELETE FROM {table} WHERE {condition}", params
                    ).rowcount
            if dry_run:
                conn.rollback()
            else:
                conn.execute(_RECORD, params)  # committed with the deletes, as the block ends
    except psycopg.Error as exc:
        raise AuditError(f"could not prune the audit log: {str(exc).strip()}") from exc
    return Pruned(
        params["cutoff"],
        params["events"],
        params["sessions"],
        params["caller_charges"],
        dry_run=dry_run,
    )
