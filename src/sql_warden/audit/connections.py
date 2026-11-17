"""How the audit sink and the budget store reach the audit database.

An action gets two tries: a connection that broke (the database restarted, say) is given up
and the action runs once more on a fresh one, before the failure is reported.
"""

import threading
from collections.abc import Callable
from typing import Any, Protocol

import psycopg


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

    def close(self) -> None: ...


def _why(exc: psycopg.Error) -> str:
    return str(exc).strip()  # psycopg names the host, never a password


class OneConnection:
    """One connection, opened when first needed and shared by threads one at a time."""

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
