"""Connection pools for the Postgres databases a server talks to.

A server answers many requests; opening a connection for each costs a handshake,
authentication and a new backend process on the database, every time. A pool keeps a few
open and lends them out. What makes that safe is that a connection carries nothing from one
borrower to the next: each is reset as it comes back, and checked as it goes out.

Commands run by hand (query, check, tables) answer one request and exit, so they don't pool.
"""

from dataclasses import dataclass, field
from typing import Any

import psycopg
from psycopg_pool import ConnectionPool


@dataclass(frozen=True)
class PoolSettings:
    max_size: int = 10
    """The most connections open at once."""
    max_idle_s: float = 300.0
    """An idle connection is closed after this long, down to none."""
    max_lifetime_s: float = 1800.0
    """A connection is replaced after this long."""
    timeout_s: float = 5.0
    """How long a borrower waits when every connection is in use."""


@dataclass(frozen=True)
class PoolStats:
    """What a pool is doing right now, for /metrics."""

    open: int
    """Connections open, in use or idle."""
    in_use: int
    """Lent out, or being reset in the background on their way back."""
    waiting: int
    """Borrowers waiting for a connection."""
    timeouts: int
    """Borrowers, since the pool opened, that got no connection in time."""


def reset(conn: psycopg.Connection[Any]) -> None:
    """Put a returned connection back as it was opened: no session settings, prepared
    statements, cursors, temporary tables, advisory locks or LISTENs left from the last
    borrower. Through psycopg, which forgets its own prepared statements when it sees
    DISCARD ALL, so it never asks for one the server has dropped."""
    was = conn.autocommit
    conn.autocommit = True  # DISCARD ALL can't run in a transaction
    try:
        conn.execute("DISCARD ALL")
    finally:
        conn.autocommit = was


@dataclass
class Reach:
    """How the pool's last attempt to connect went: why it failed, or None if it didn't.
    The pool connects in the background, so a borrower that waited in vain learns from this
    whether the database is unreachable or merely busy."""

    failure: str | None = field(default=None)


def _recording(reach: Reach) -> type[psycopg.Connection[Any]]:
    class Recording(psycopg.Connection[Any]):
        @classmethod
        def connect(cls, *args: Any, **kwargs: Any) -> Any:
            try:
                conn = super().connect(*args, **kwargs)
            except psycopg.Error as exc:
                reach.failure = str(exc).strip()  # psycopg names the host, never a password
                raise
            reach.failure = None
            return conn

    return Recording


def open_pool(
    dsn: str,
    settings: PoolSettings,
    *,
    name: str,
    connect_timeout_s: int,
    autocommit: bool = False,
) -> tuple[ConnectionPool[psycopg.Connection[Any]], Reach]:
    """A pool that starts empty and opens connections as they are needed, up to max_size,
    and how its attempts to connect are going. Each connection is checked as it is lent
    (one the server closed is replaced, not handed out) and reset as it comes back."""
    reach = Reach()
    pool = ConnectionPool(
        dsn,
        connection_class=_recording(reach),
        kwargs={"connect_timeout": connect_timeout_s, "autocommit": autocommit},
        min_size=0,
        max_size=settings.max_size,
        max_idle=settings.max_idle_s,
        max_lifetime=settings.max_lifetime_s,
        timeout=settings.timeout_s,
        check=ConnectionPool.check_connection,
        reset=reset,
        name=name,
        open=True,
    )
    return pool, reach


def stats(pool: ConnectionPool[Any]) -> PoolStats:
    found = pool.get_stats()
    size, available = found.get("pool_size", 0), found.get("pool_available", 0)
    return PoolStats(
        open=size,
        in_use=max(size - available, 0),
        waiting=found.get("requests_waiting", 0),
        timeouts=found.get("requests_errors", 0),
    )
