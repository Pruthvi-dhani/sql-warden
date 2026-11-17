"""How sql-warden holds up under many callers at once.

N threads each send queries through a Warden, as the HTTP server's worker threads do, and the
script reports requests per second, latency, and how many connections the warehouse saw:
how many it opened over the run, and the most it had open at once.

    uv run python dev/loadtest.py                         # throwaway containers, seeded as the demo
    uv run python dev/loadtest.py --callers 32 --requests 4000
    uv run python dev/loadtest.py --budgets               # each query also charged to a budget
    uv run python dev/loadtest.py --audit-latency-ms 0.5  # as if the audit database were farther
    uv run python dev/loadtest.py --config warden.yaml --profile public \\
        --watch-dsn postgresql://warehouse_admin:...@localhost:5433/warehouse

By default it starts its own warehouse and audit databases (Docker, with the integration
tests' image and the demo seed) and removes them after, so nothing is recorded anywhere that
lasts. Given --config, it runs against that setup instead and every request is recorded in
its audit database, as any request would be. --watch-dsn is a role there that can read
pg_stat_activity, for the connection counts.

On one machine the audit database is a fraction of a millisecond away, where a managed one
in another account is more. --audit-latency-ms puts a proxy of its own (a process of its
own, so it takes no time from the server's) between them that holds everything sent either
way for that long.
"""

import argparse
import asyncio
import multiprocessing
import socket
import statistics
import sys
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sql_warden.cli import build_warden, open_audit  # noqa: E402
from sql_warden.config import WardenConfig, load_config  # noqa: E402

DEFAULT_SQL = "select id, name, price_cents from products where id = 42"


@dataclass(frozen=True)
class Setup:
    config: WardenConfig
    profile: str | None
    watch_dsn: str | None
    """A connection to the warehouse that can see every session, for counting them."""
    watched_role: str | None
    """The role whose connections are counted."""


def _delay(listen: socket.socket, host: str, port: int, delay_s: float) -> None:
    """Forward every connection made to listen to host:port, each chunk either way sent on
    delay_s after it arrived, in order."""

    async def forward(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        held: asyncio.Queue[tuple[float, bytes]] = asyncio.Queue()

        async def send() -> None:
            while True:
                due, data = await held.get()
                await asyncio.sleep(max(due - time.monotonic(), 0))
                if not data:
                    writer.close()
                    return
                writer.write(data)
                await writer.drain()

        sender = asyncio.ensure_future(send())
        while data := await reader.read(65536):
            await held.put((time.monotonic() + delay_s, data))
        await held.put((time.monotonic() + delay_s, b""))
        await sender

    async def connected(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        server_reader, server_writer = await asyncio.open_connection(host, port)
        await asyncio.gather(
            forward(reader, server_writer), forward(server_reader, writer), return_exceptions=True
        )

    async def serve() -> None:
        async with await asyncio.start_server(connected, sock=listen) as server:
            await server.serve_forever()

    asyncio.run(serve())


@contextmanager
def delayed(dsn: str, latency_ms: float) -> Iterator[str]:
    """dsn, reached through a proxy that adds latency_ms each way."""
    target = conninfo_to_dict(dsn)
    listen = socket.create_server(("127.0.0.1", 0))
    proxy = multiprocessing.Process(
        target=_delay,
        args=(listen, str(target["host"]), int(str(target["port"])), latency_ms / 1000),
        daemon=True,
    )
    proxy.start()
    try:
        yield make_conninfo(dsn, host="127.0.0.1", port=listen.getsockname()[1])
    finally:
        proxy.terminate()
        listen.close()


@contextmanager
def throwaway(
    pool_size: int | None = None, *, budgets: bool = False, audit_latency_ms: float = 0
) -> Iterator[Setup]:
    """A warehouse and an audit database of its own, gone when the run ends. With budgets,
    the profile has a session budget too large to run out, so every query is also charged
    to it in the audit database, as a profile with budgets is."""
    from testcontainers.community.postgres import PostgresContainer

    image = "postgres:16-alpine"  # the integration tests' (tests/integration/conftest.py)
    seed = ROOT / "dev" / "warehouse_seed.sql"
    warehouse = PostgresContainer(
        image,
        username="warehouse_admin",
        password="warehouse_admin",
        dbname="warehouse",
        driver=None,
    ).with_volume_mapping(str(seed), "/docker-entrypoint-initdb.d/01_warehouse_seed.sql", "ro")
    audit = PostgresContainer(
        image, username="warden_audit", password="warden_audit", dbname="audit", driver=None
    )
    with ExitStack() as running:
        running.enter_context(warehouse)
        running.enter_context(audit)
        audit_dsn = audit.get_connection_url()
        if audit_latency_ms:
            audit_dsn = running.enter_context(delayed(audit_dsn, audit_latency_ms))
        host = warehouse.get_container_host_ip()
        port = warehouse.get_exposed_port(5432)
        reader = f"postgresql://warden_reader:warden_reader@{host}:{port}/warehouse"
        config = WardenConfig.model_validate(
            {
                "version": 1,
                "warehouse": {
                    "dsn": reader,
                    **({"pool": {"max_size": pool_size}} if pool_size else {}),
                },
                "audit": {"dsn": audit_dsn},
                "profiles": {
                    "public": {
                        "tables": {"public.products": ["id", "name", "price_cents"]},
                        **({"budgets": {"max_queries": 10**9}} if budgets else {}),
                    }
                },
                "default_profile": "public",
            }
        )
        yield Setup(config, "public", warehouse.get_connection_url(), "warden_reader")


class Watcher:
    """Counts the watched role's connections to the warehouse while the run goes on."""

    def __init__(self, dsn: str, role: str) -> None:
        self._dsn = dsn
        self._conn = psycopg.connect(dsn, autocommit=True)
        self._role = role
        self.peak = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._watch, daemon=True)
        self._opened_before = self.opened()

    def opened(self) -> int:
        """Connections the warehouse has accepted since it started, every role's."""
        row = self._conn.execute(
            "SELECT sessions FROM pg_stat_database WHERE datname = current_database()"
        ).fetchone()
        return int(row[0]) if row else 0

    def __enter__(self) -> "Watcher":
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join()
        # Less the watcher's own second connection.
        self.opened_during = self.opened() - self._opened_before - 1
        self._conn.close()

    def _watch(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            while not self._stop.is_set():
                row = conn.execute(
                    "SELECT count(*) FROM pg_stat_activity WHERE usename = %s", (self._role,)
                ).fetchone()
                self.peak = max(self.peak, int(row[0]) if row else 0)
                time.sleep(0.02)


def run(setup: Setup, *, callers: int, requests: int, sql: str) -> dict[str, Any]:
    audit = open_audit(setup.config)
    warden = build_warden(setup.config, setup.profile, audit=audit, serving=True)
    latencies: list[float] = []
    failed = 0
    lock = threading.Lock()

    def one(n: int) -> None:
        nonlocal failed
        started = time.perf_counter()
        outcome = warden.run(sql, client="loadtest", session_id=f"load-{n % callers}")
        took = time.perf_counter() - started
        with lock:
            latencies.append(took)
            failed += outcome.result is None

    warden.run(sql, client="loadtest")  # warm: the catalog is read once, and cached
    watcher = (
        Watcher(setup.watch_dsn, setup.watched_role)
        if setup.watch_dsn and setup.watched_role
        else None
    )
    started = time.perf_counter()
    if watcher is not None:
        watcher.__enter__()
    try:
        with ThreadPoolExecutor(max_workers=callers) as pool:
            list(pool.map(one, range(requests)))
    finally:
        elapsed = time.perf_counter() - started
        if watcher is not None:
            watcher.__exit__()
        warden.close()
        audit.close()
    ordered = sorted(latencies)

    def percentile(p: float) -> float:
        return ordered[min(len(ordered) - 1, int(p * len(ordered)))] * 1000

    return {
        "callers": callers,
        "requests": requests,
        "failed": failed,
        "per_second": requests / elapsed,
        "p50_ms": statistics.median(ordered) * 1000,
        "p95_ms": percentile(0.95),
        "p99_ms": percentile(0.99),
        "connections_opened": None if watcher is None else watcher.opened_during,
        "connections_peak": None if watcher is None else watcher.peak,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--callers", type=int, default=16, help="threads at once (16)")
    parser.add_argument("--requests", type=int, default=2000, help="queries in all (2000)")
    parser.add_argument("--sql", default=DEFAULT_SQL, help="the query each sends")
    parser.add_argument(
        "--pool-size", type=int, help="throwaway only: warehouse.pool.max_size (its default)"
    )
    parser.add_argument(
        "--budgets", action="store_true", help="throwaway only: charge each query to a budget"
    )
    parser.add_argument(
        "--audit-latency-ms",
        type=float,
        default=0,
        help="throwaway only: added each way between the server and its audit database",
    )
    parser.add_argument("--config", type=Path, help="run against this setup, not throwaway ones")
    parser.add_argument("--profile", help="with --config: the profile to run as")
    parser.add_argument(
        "--watch-dsn", help="with --config: a warehouse role that sees all sessions"
    )
    parser.add_argument("--watch-role", help="with --config: whose connections to count")
    args = parser.parse_args()

    if args.config is None:
        with throwaway(
            args.pool_size, budgets=args.budgets, audit_latency_ms=args.audit_latency_ms
        ) as setup:
            report = run(setup, callers=args.callers, requests=args.requests, sql=args.sql)
    else:
        setup = Setup(load_config(args.config), args.profile, args.watch_dsn, args.watch_role)
        report = run(setup, callers=args.callers, requests=args.requests, sql=args.sql)
    width = max(len(key) for key in report)
    for key, value in report.items():
        shown = f"{value:,.1f}" if isinstance(value, float) else value
        print(f"{key:<{width}}  {shown}")


if __name__ == "__main__":
    main()
