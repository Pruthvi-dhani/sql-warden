"""Sessions: one caller's run of requests, and what it has used so far.

A session is one MCP connection, or the CLI calls made with the same `--session`. Every request
belongs to one, and the audit log records which. The store keeps each session's usage, for the
budget check to hold against the profile's limits.

It also keeps what each caller (a token's identity) has used, charge by charge, for budgets
over a rolling window: those hold across all of a caller's sessions, so connecting again
doesn't start a fresh one.
"""

import re
import threading
import time
import uuid
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, fields
from typing import Literal, Protocol

from sql_warden.config import BudgetConfig

_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
MAX_SESSIONS = 10_000
"""How many sessions MemorySessionStore keeps before it forgets the least recently charged."""


class SessionStoreError(Exception):
    """A session's usage could not be read or charged, so its budget can't be checked. The
    message is safe to show."""


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


def reached(usage: Usage, budget: BudgetConfig) -> str | None:
    """The first limit of budget that usage has reached or passed, or None if there is room
    under them all. A session that has reached a limit is done: nothing more runs in it."""
    for limit, used in _LIMITS:
        most = getattr(budget, limit)
        if most is not None and getattr(usage, used) >= most:
            return limit
    return None


@dataclass(frozen=True)
class CallerStatus:
    """What a caller has used over the window, held against their budget."""

    name: str
    window_hours: float
    usage: Usage
    limits: BudgetConfig

    @property
    def exhausted(self) -> str | None:
        return reached(self.usage, self.limits)

    def lines(self) -> tuple[tuple[str, float, float | None], ...]:
        return tuple(
            (used, getattr(self.usage, used), getattr(self.limits, limit))
            for limit, used in _LIMITS
        )


@dataclass(frozen=True)
class BudgetStatus:
    """A session's usage, held against its budget, and its caller's if they have one."""

    usage: Usage
    limits: BudgetConfig
    caller: CallerStatus | None = None

    @property
    def exhausted(self) -> str | None:
        """The limit the session has reached, e.g. "max_queries", if any."""
        return reached(self.usage, self.limits)

    def lines(self) -> tuple[tuple[str, float, float | None], ...]:
        """(what, used, limit) for queries, total_cost, rows_returned and refusals; the
        limit is None where there is none."""
        return tuple(
            (used, getattr(self.usage, used), getattr(self.limits, limit))
            for limit, used in _LIMITS
        )


@dataclass(frozen=True)
class CallerCharge:
    """The caller a charge is for, as well as the session."""

    name: str
    window_s: float
    """How far back their use counts."""
    within: BudgetConfig | None = None
    """Their limits over the window: as for the session's, the charge is made only if their
    use stays within them. None to count it without holding it to anything."""


@dataclass(frozen=True)
class Charge:
    """What came of charging a session."""

    usage: Usage
    """The session's usage now: with the charge if it was made, as it was if not."""
    exceeded: str | None = None
    """The limit the charge would have gone over, e.g. "max_queries". Then nothing was
    charged, to the session or the caller."""
    by: Literal["session", "caller"] | None = None
    """Whose limit that is: the session's, or the caller's over the window."""
    caller_usage: Usage | None = None
    """The caller's use over the window now, if a caller was charged."""

    @property
    def made(self) -> bool:
        return self.exceeded is None


class SessionStore(Protocol):
    """Each session's usage. In memory for one server; a shared database once several servers
    serve the same sessions, which is why charging is one atomic step here rather than a read
    followed by a write.

    Either method raises SessionStoreError if the usage can't be read or kept."""

    def usage(self, session_id: str) -> Usage:
        """What the session has used so far. Nothing, for a session never charged."""
        ...

    def caller_usage(self, name: str, window_s: float) -> Usage:
        """What the caller has used in the last window_s seconds, over all their sessions."""
        ...

    def charge(
        self,
        session_id: str,
        spent: Usage,
        *,
        within: BudgetConfig | None = None,
        caller: CallerCharge | None = None,
    ) -> Charge:
        """Add spent to the session's usage, and the caller's if given, and return the new
        totals.

        With `within`, only if the session's total stays within every limit of that budget,
        and the caller's within theirs: otherwise nothing is added to either, and the Charge
        names the limit and whose it is. Checking and adding are one step, so requests
        charging at the same time can't take a session or a caller over a limit between
        them."""
        ...


class MemorySessionStore:
    """Usage kept in this process, and not shared with other servers.

    Thread-safe. It keeps at most max_sessions sessions and then forgets the one charged
    longest ago, so a server that many clients connect to doesn't grow without end.

    restore says what a session had already used when this store first hears of it: the
    Warden reads that from the audit log, so a budget outlives the process that counted it.
    It is asked once per session, and again for one that was forgotten. Without it, an
    unknown or forgotten session starts from nothing.
    """

    def __init__(
        self,
        *,
        max_sessions: int = MAX_SESSIONS,
        restore: Callable[[str], Usage] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be at least 1")
        self._max_sessions = max_sessions
        self._restore = restore
        self._clock = clock
        self._usage: OrderedDict[str, Usage] = OrderedDict()
        self._callers: OrderedDict[str, deque[tuple[float, Usage]]] = OrderedDict()
        """Each caller's charges, oldest first, while they are within the window."""
        self._lock = threading.Lock()

    def usage(self, session_id: str) -> Usage:
        with self._lock:
            return self._used(session_id)

    def caller_usage(self, name: str, window_s: float) -> Usage:
        with self._lock:
            return self._caller_used(name, window_s)

    def _caller_used(self, name: str, window_s: float) -> Usage:
        charges = self._callers.get(name)
        if charges is None:
            return Usage()
        since = self._clock() - window_s
        while charges and charges[0][0] <= since:
            charges.popleft()  # out of the window: it no longer counts, or needs keeping
        total = Usage()
        for _, spent in charges:
            total += spent
        return total

    def _used(self, session_id: str) -> Usage:
        """The session's usage, restored first if this store doesn't know the session. Held
        under the lock, so two requests can't both restore it and one lose its charge."""
        used = self._usage.get(session_id)
        if used is not None:
            return used
        if self._restore is None:
            return Usage()  # nothing to remember until it is charged
        used = self._restore(session_id)
        self._keep(session_id, used)  # kept even if nothing, so it is asked only once
        return used

    def _keep(self, session_id: str, used: Usage) -> None:
        self._usage[session_id] = used
        self._usage.move_to_end(session_id)
        while len(self._usage) > self._max_sessions:
            self._usage.popitem(last=False)

    def charge(
        self,
        session_id: str,
        spent: Usage,
        *,
        within: BudgetConfig | None = None,
        caller: CallerCharge | None = None,
    ) -> Charge:
        if any(getattr(spent, field.name) < 0 for field in fields(Usage)):
            raise ValueError("a charge can't be negative: usage only grows")
        with self._lock:
            used = self._used(session_id)
            total = used + spent
            caller_used = (
                None if caller is None else self._caller_used(caller.name, caller.window_s)
            )
            if within is not None:
                exceeded = over(total, within)
                if exceeded is not None:
                    return Charge(used, exceeded, "session", caller_used)
            if caller is not None and caller_used is not None and caller.within is not None:
                exceeded = over(caller_used + spent, caller.within)
                if exceeded is not None:
                    return Charge(used, exceeded, "caller", caller_used)
            self._keep(session_id, total)
            if caller is None or caller_used is None:
                return Charge(total)
            if spent != Usage():
                charges = self._callers.setdefault(caller.name, deque())
                charges.append((self._clock(), spent))
                self._callers.move_to_end(caller.name)
                while len(self._callers) > self._max_sessions:
                    self._callers.popitem(last=False)
            return Charge(total, caller_usage=caller_used + spent)

    def __len__(self) -> int:
        with self._lock:
            return len(self._usage)
