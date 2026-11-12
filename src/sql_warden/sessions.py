"""Sessions: one caller's run of requests, and what it has used so far.

A session is one MCP connection, or the CLI calls made with the same `--session`. Every request
belongs to one, and the audit log records which. The store keeps each session's usage, for the
budget check to hold against the profile's limits.
"""

import re
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass, fields
from typing import Protocol

from sql_warden.config import BudgetConfig

_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
MAX_SESSIONS = 10_000
"""How many sessions MemorySessionStore keeps before it forgets the least recently charged."""


def new_session_id() -> str:
    """An id for a session nobody named: random, so it can't collide with or be guessed from
    another."""
    return uuid.uuid4().hex


def valid_session_id(session_id: str) -> bool:
    """True if session_id can name a session: up to 64 letters, digits, '.', '_', ':' or '-',
    starting with a letter or digit. Ids end up in the audit log and on command lines."""
    return _SESSION_ID.fullmatch(session_id) is not None


@dataclass(frozen=True)
class Usage:
    """What a session has used, or what one request adds to that."""

    queries: int = 0
    """Queries that were allowed and sent to the database."""
    total_cost: float = 0.0
    """The sum of their estimated costs, in the planner's units."""
    rows_returned: int = 0
    refusals: int = 0
    """Refused requests, dry runs included."""

    def __add__(self, other: "Usage") -> "Usage":
        return Usage(
            *(getattr(self, field.name) + getattr(other, field.name) for field in fields(Usage))
        )


# Each limit of a budget, and the part of the usage it caps.
_LIMITS = (
    ("max_queries", "queries"),
    ("max_total_cost", "total_cost"),
    ("max_rows_returned", "rows_returned"),
    ("max_refusals", "refusals"),
)


def over(usage: Usage, budget: BudgetConfig) -> str | None:
    """The first limit of budget that usage is over, e.g. "max_queries", or None if it is
    within them all. Equal to a limit is within it."""
    for limit, used in _LIMITS:
        most = getattr(budget, limit)
        if most is not None and getattr(usage, used) > most:
            return limit
    return None


@dataclass(frozen=True)
class Charge:
    """What came of charging a session."""

    usage: Usage
    """The session's usage now: with the charge if it was made, as it was if not."""
    exceeded: str | None = None
    """The limit the charge would have gone over, e.g. "max_queries". Then nothing was
    charged."""

    @property
    def made(self) -> bool:
        return self.exceeded is None


class SessionStore(Protocol):
    """Each session's usage. In memory for one server; a shared database once several servers
    serve the same sessions, which is why charging is one atomic step here rather than a read
    followed by a write."""

    def usage(self, session_id: str) -> Usage:
        """What the session has used so far. Nothing, for a session never charged."""
        ...

    def charge(
        self, session_id: str, spent: Usage, *, within: BudgetConfig | None = None
    ) -> Charge:
        """Add spent to the session's usage and return the new total.

        With `within`, only if the total stays within every limit of that budget: otherwise
        nothing is added, and the Charge names the limit. Checking and adding are one step, so
        callers charging at the same time can't take a session over a limit between them."""
        ...


class MemorySessionStore:
    """Usage kept in this process: gone when it stops, and not shared with other servers.

    Thread-safe. It keeps at most max_sessions sessions and then forgets the one charged
    longest ago, so a server that many clients connect to doesn't grow without end. A
    forgotten session starts again from nothing, as a new connection would anyway.
    """

    def __init__(self, *, max_sessions: int = MAX_SESSIONS) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be at least 1")
        self._max_sessions = max_sessions
        self._usage: OrderedDict[str, Usage] = OrderedDict()
        self._lock = threading.Lock()

    def usage(self, session_id: str) -> Usage:
        with self._lock:
            return self._usage.get(session_id, Usage())

    def charge(
        self, session_id: str, spent: Usage, *, within: BudgetConfig | None = None
    ) -> Charge:
        if any(getattr(spent, field.name) < 0 for field in fields(Usage)):
            raise ValueError("a charge can't be negative: usage only grows")
        with self._lock:
            used = self._usage.get(session_id, Usage())
            total = used + spent
            if within is not None:
                exceeded = over(total, within)
                if exceeded is not None:
                    return Charge(used, exceeded)
            self._usage[session_id] = total
            self._usage.move_to_end(session_id)
            while len(self._usage) > self._max_sessions:
                self._usage.popitem(last=False)
            return Charge(total)

    def __len__(self) -> int:
        with self._lock:
            return len(self._usage)
