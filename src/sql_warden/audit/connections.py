"""How the audit sink and the budget store reach the audit database: one connection of their
own for a command run by hand, a pool for a server.

Either way an action gets two tries: a connection that broke (the database restarted, say)
is given up and the action runs once more on a fresh one, before the failure is reported.
"""

import threading
from collections.abc import Callable
from typing import Any, Protocol

import psycopg
from psycopg_pool import PoolClosed, PoolTimeout

from sql_warden.pools import PoolSettings, PoolStats, open_pool, stats, why_none

_WHERE = "the audit database"


class Connections(Protocol):
    def attempt[T](
        self,
        action: Callable[[psycopg.Connection[Any]], T],
        what: str,
        error: Callable[[str], Exception],
    ) -> T:
        """action's answer, on an autocommit connection; or raise error("<what>: <why>"),
        with a reason that is safe to show."""
        ...

    def stats(self) -> PoolStats | None:
        """What the pool is doing, if there is one."""
        ...

    def close(self) -> None: ...


def _why(exc: psycopg.Error) -> str:
    return str(exc).strip()  # psycopg names the host, never a password


class OneConnection:
    """One connection, opened when first needed and shared by threads one at a time: for a
    command that answers a request or two and exits."""

    def __init__(self, dsn: str, *, connect_timeout_s: int) -> None:
        self._dsn = dsn
        self._connect_timeout_s = connect_timeout_s
        self._conn: psycopg.Connection[Any] | None = None
        self._lock = threading.Lock()

    def attempt[T](
        self,
        action: Callable[[psycopg.Connection[Any]], T],
        what: str,
        error: Callable[[str], Exception],
    ) -> T:
        with self._lock:
            try:
                return action(self._connection())
            except psycopg.OperationalError:
                self._drop()
            except psycopg.Error as exc:
                raise error(f"{what}: {_why(exc)}") from exc
            try:
                return action(self._connection())
            except psycopg.Error as exc:
                self._drop()
                raise error(f"{what}: {_why(exc)}") from exc

    def stats(self) -> PoolStats | None:
        return None

    def close(self) -> None:
        with self._lock:
            self._drop()

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


class PooledConnections:
    """A pool of connections, each lent to one action at a time: for a server, whose
    requests then reach the audit database side by side rather than in a queue.

    The connections are not reset between borrowers. Nothing runs on them but sql-warden's
    own statements, and each leaves nothing behind: what one sets or locks is the
    transaction's (SET LOCAL, pg_advisory_xact_lock), and gone as it ends. Their prepared
    statements are kept, which is most of the reason to reuse them.

    Nor are they checked as they are lent, as the warehouse's are: that is a round trip
    more for every record and charge, which are a round trip or two themselves. Instead an
    action that finds its connection broken has every idle one checked (after a restart of
    the database they are all broken) before its second try, which then gets one that
    works or a new one."""

    def __init__(
        self, dsn: str, settings: PoolSettings, *, name: str, connect_timeout_s: int
    ) -> None:
        self._pool, self._reach = open_pool(
            dsn,
            settings,
            name=name,
            connect_timeout_s=connect_timeout_s,
            autocommit=True,
            resets=False,
            checks=False,
        )
        self._timeout_s = settings.timeout_s

    def attempt[T](
        self,
        action: Callable[[psycopg.Connection[Any]], T],
        what: str,
        error: Callable[[str], Exception],
    ) -> T:
        for last in (False, True):
            try:
                with self._pool.connection() as conn:
                    try:
                        return action(conn)
                    except psycopg.OperationalError:
                        conn.close()  # broken: the pool discards it rather than lend it again
                        raise
            except (PoolTimeout, PoolClosed) as exc:
                # Waited as long as a request may: another wait would only double it.
                why = why_none(exc, self._reach, self._timeout_s, _WHERE)
                raise error(f"{what}: {why}") from exc
            except psycopg.OperationalError as exc:
                if last:
                    raise error(f"{what}: {_why(exc)}") from exc
                self._pool.check()  # the rest that broke with it are replaced, not lent
            except psycopg.Error as exc:
                raise error(f"{what}: {_why(exc)}") from exc
        raise AssertionError("unreachable: the second try returns or raises")

    def stats(self) -> PoolStats | None:
        return stats(self._pool)

    def close(self) -> None:
        self._pool.close()
