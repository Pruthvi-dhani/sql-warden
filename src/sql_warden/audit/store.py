"""The session store in the audit database: budgets shared by every server recording there.

A MemorySessionStore holds a session's budget within one process. Behind a load balancer the
same session (or the same caller) can reach several, and each would let it spend its whole
budget. Here every charge is one transaction on rows all of them share: the session's row is
locked, and the caller's charges by an advisory lock, before anything is checked, so no two
servers can each spend the same last query.
"""

import threading
from collections.abc import Callable, Collection
from typing import Any

import psycopg

from sql_warden.audit.sink import _USAGE
from sql_warden.config import BudgetConfig
from sql_warden.sessions import CallerCharge, Charge, SessionStoreError, Usage, over

_SELECT = """
    SELECT queries, total_cost, rows_returned, refusals FROM session_usage
    WHERE profile = %(profile)s AND session_id = %(session_id)s
"""
_LOCK = _SELECT + " FOR UPDATE"
# The first charge to a session starts it from what the audit log says it used: what it had
# before this table, or before this server.
_SEED = f"""
    INSERT INTO session_usage (profile, session_id, queries, total_cost, rows_returned, refusals)
    SELECT %(profile)s, %(session_id)s, used.* FROM ({_USAGE}) AS used
    ON CONFLICT (profile, session_id) DO NOTHING
"""
_ADD = """
    UPDATE session_usage SET
        queries = queries + %(queries)s,
        total_cost = total_cost + %(total_cost)s,
        rows_returned = rows_returned + %(rows_returned)s,
        refusals = refusals + %(refusals)s,
        updated_at = now()
    WHERE profile = %(profile)s AND session_id = %(session_id)s
"""
# One caller's charges, one at a time, whichever server takes them.
_CALLER_LOCK = "SELECT pg_advisory_xact_lock(hashtextextended(%(lock)s, 0))"
_CALLER_FORGET = """
    DELETE FROM caller_charges
    WHERE profile = %(profile)s AND caller = %(caller)s
      AND ts <= now() - make_interval(secs => %(window_s)s)
"""
_CALLER_USAGE = """
    SELECT coalesce(sum(queries), 0), coalesce(sum(total_cost), 0),
           coalesce(sum(rows_returned), 0), coalesce(sum(refusals), 0)
    FROM caller_charges
    WHERE profile = %(profile)s AND caller = %(caller)s
      AND ts > now() - make_interval(secs => %(window_s)s)
"""
_CALLER_ADD = """
    INSERT INTO caller_charges (profile, caller, queries, total_cost, rows_returned, refusals)
    VALUES (%(profile)s, %(caller)s, %(queries)s, %(total_cost)s, %(rows_returned)s,
            %(refusals)s)
"""


def _usage(row: Any) -> Usage:
    queries, total_cost, rows_returned, refusals = row
    return Usage(int(queries), float(total_cost), int(rows_returned), int(refusals))


class PostgresSessionStore:
    """A SessionStore for one profile, in the audit database (its tables come with the audit
    schema). One connection, shared by threads and replaced once if it breaks, as the audit
    sink's is.

    not_counted are the refusal codes a session's budget doesn't count, for reading a
    session's earlier usage out of the audit log."""

    def __init__(
        self,
        dsn: str,
        *,
        profile: str,
        not_counted: Collection[str] = (),
        connect_timeout_s: int = 5,
    ) -> None:
        self._dsn = dsn
        self._profile = profile
        self._not_counted = [str(code) for code in not_counted]
        self._connect_timeout_s = connect_timeout_s
        self._conn: psycopg.Connection[Any] | None = None
        self._lock = threading.Lock()

    def usage(self, session_id: str) -> Usage:
        params = self._params(session_id)

        def read(conn: psycopg.Connection[Any]) -> Usage:
            row = conn.execute(_SELECT, params).fetchone()
            if row is None:  # never charged here: what the audit log says it used
                row = conn.execute(_USAGE, params).fetchone()
            return _usage(row)

        return self._attempt(read, "could not read the session's usage")

    def caller_usage(self, name: str, window_s: float) -> Usage:
        params = {**self._params(), "caller": name, "window_s": window_s}
        return self._attempt(
            lambda conn: _usage(conn.execute(_CALLER_USAGE, params).fetchone()),
            "could not read the caller's usage",
        )

    def charge(
        self,
        session_id: str,
        spent: Usage,
        *,
        within: BudgetConfig | None = None,
        caller: CallerCharge | None = None,
    ) -> Charge:
        if min(spent.queries, spent.total_cost, spent.rows_returned, spent.refusals) < 0:
            raise ValueError("a charge can't be negative: usage only grows")
        params = {
            **self._params(session_id),
            "queries": spent.queries,
            "total_cost": spent.total_cost,
            "rows_returned": spent.rows_returned,
            "refusals": spent.refusals,
        }

        def charge(conn: psycopg.Connection[Any]) -> Charge:
            with conn.transaction():
                row = conn.execute(_LOCK, params).fetchone()
                if row is None:
                    conn.execute(_SEED, params)
                    row = conn.execute(_LOCK, params).fetchone()
                used = _usage(row)
                caller_used = None
                if caller is not None:
                    mine = {
                        **params,
                        "caller": caller.name,
                        "window_s": caller.window_s,
                        "lock": f"sql-warden caller {self._profile}:{caller.name}",
                    }
                    conn.execute(_CALLER_LOCK, mine)
                    conn.execute(_CALLER_FORGET, mine)
                    caller_used = _usage(conn.execute(_CALLER_USAGE, mine).fetchone())
                if within is not None:
                    exceeded = over(used + spent, within)
                    if exceeded is not None:
                        return Charge(used, exceeded, "session", caller_used)
                if caller is not None and caller_used is not None and caller.within is not None:
                    exceeded = over(caller_used + spent, caller.within)
                    if exceeded is not None:
                        return Charge(used, exceeded, "caller", caller_used)
                conn.execute(_ADD, params)
                if caller is None or caller_used is None:
                    return Charge(used + spent)
                if spent != Usage():
                    conn.execute(_CALLER_ADD, mine)
                return Charge(used + spent, caller_usage=caller_used + spent)

        return self._attempt(charge, "could not charge the session's budget")

    def close(self) -> None:
        with self._lock:
            self._drop()

    def _params(self, session_id: str | None = None) -> dict[str, Any]:
        return {
            "profile": self._profile,
            "session_id": session_id,
            "not_counted": self._not_counted,
        }

    def _attempt[T](self, action: Callable[[psycopg.Connection[Any]], T], what: str) -> T:
        # Two tries, as the audit sink makes: a connection that broke since last time gets
        # one fresh replacement. A charge whose commit was lost may then be counted twice,
        # which errs the safe way: usage only ever reads high.
        with self._lock:
            try:
                return action(self._connection())
            except psycopg.OperationalError:
                self._drop()
            except psycopg.Error as exc:
                raise SessionStoreError(f"{what}: {str(exc).strip()}") from exc
            try:
                return action(self._connection())
            except psycopg.Error as exc:
                self._drop()
                raise SessionStoreError(f"{what}: {str(exc).strip()}") from exc

    def _connection(self) -> psycopg.Connection[Any]:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg.connect(
                self._dsn, autocommit=True, connect_timeout=self._connect_timeout_s
            )
        return self._conn

    def _drop(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
