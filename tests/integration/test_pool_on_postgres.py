"""The warehouse engine's connection pool, against real Postgres: how many connections it
opens, what a connection carries from one borrower to the next (nothing), and what happens
when the pool is full, a connection dies, or the pool is closed."""

import threading
import time
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest

from sql_warden.audit import MemoryAuditSink
from sql_warden.engines import EngineUnavailable, QueryTimeout
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.metrics import Metrics
from sql_warden.models import RefusalCode
from sql_warden.pools import PoolSettings
from sql_warden.profiles import Access
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration

SQL = "select id, name from products where id = 7"
PRODUCTS = Access({("public", "products"): frozenset({"id", "name", "price_cents"})})


def _admin(warehouse: Warehouse, sql: str, params: Any = None) -> Any:
    with psycopg.connect(warehouse.admin_dsn, autocommit=True) as conn:
        row = conn.execute(sql, params).fetchone()
    return None if row is None else row[0]


def _opened(warehouse: Warehouse) -> int:
    """Connections the warehouse has accepted so far, every role's (this one's included)."""
    return int(
        _admin(warehouse, "SELECT sessions FROM pg_stat_database WHERE datname = 'warehouse'")
    )


def _open_as(warehouse: Warehouse, role: str) -> int:
    return int(
        _admin(warehouse, "SELECT count(*) FROM pg_stat_activity WHERE usename = %s", (role,))
    )


@pytest.fixture
def engines() -> Iterator[list[PostgresEngine]]:
    """Every pooled engine a test makes, closed after it."""
    made: list[PostgresEngine] = []
    yield made
    for engine in made:
        engine.close()


def _pooled(
    engines: list[PostgresEngine], dsn: str, size: int = 4, **settings: Any
) -> PostgresEngine:
    pool = PoolSettings(
        max_size=size, **{k: settings.pop(k) for k in list(settings) if k.endswith("_s")}
    )
    engine = PostgresEngine(dsn, pool=pool, **settings)
    engines.append(engine)
    return engine


def _hammer(warden: Warden, *, threads: int, each: int) -> list[bool]:
    ran: list[bool] = []
    lock = threading.Lock()

    def work() -> None:
        for _ in range(each):
            outcome = warden.run(SQL)
            with lock:
                ran.append(outcome.result is not None)

    workers = [threading.Thread(target=work) for _ in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    return ran


class TestHowManyConnections:
    def test_a_pool_opens_at_most_its_size(
        self, warehouse: Warehouse, engines: list[PostgresEngine]
    ) -> None:
        engine = _pooled(engines, warehouse.public_dsn, size=4)
        warden = Warden(engine, audit=MemoryAuditSink(), access=PRODUCTS, profile="public")
        before = _opened(warehouse)
        ran = _hammer(warden, threads=16, each=13)  # 208 queries, each planned and run
        opened = _opened(warehouse) - before - 1  # less the count's own connection
        assert ran.count(True) == 208
        assert 1 <= opened <= 4 + 1  # and the catalog's first read

    def test_where_an_engine_of_its_own_opens_two_for_each_query(
        self, warehouse: Warehouse
    ) -> None:
        warden = Warden(
            PostgresEngine(warehouse.public_dsn), audit=MemoryAuditSink(), access=PRODUCTS
        )
        warden.run(SQL)  # the catalog, read once
        before = _opened(warehouse)
        ran = _hammer(warden, threads=4, each=5)
        assert ran.count(True) == 20
        assert _opened(warehouse) - before - 1 == 40


class TestWhatAConnectionCarries:
    """Nothing: whatever one borrower left on it is gone for the next."""

    def test_nothing_from_the_last_borrower(
        self, warehouse: Warehouse, engines: list[PostgresEngine]
    ) -> None:
        # The superuser, which can leave anything behind; one connection, so it is the same.
        engine = _pooled(engines, warehouse.admin_dsn, size=1)
        pool = engine._pool
        assert pool is not None
        with pool.connection() as conn:
            pid = conn.info.backend_pid
            conn.execute("SET work_mem = '77MB'")
            conn.execute("SET search_path = pg_catalog")
            conn.execute("SELECT pg_advisory_lock(4242)")
            conn.execute("PREPARE left_behind AS SELECT 1")
            conn.execute("CREATE TEMP TABLE left_behind (id int)")
            conn.execute("LISTEN left_behind")
        with pool.connection() as conn:
            assert conn.info.backend_pid == pid
            found = conn.execute(
                "SELECT current_setting('work_mem'), current_setting('search_path'), "
                "(SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = "
                "pg_backend_pid()), (SELECT count(*) FROM pg_prepared_statements), "
                "to_regclass('pg_temp.left_behind'), "
                "(SELECT count(*) FROM pg_listening_channels())"
            ).fetchone()
        assert found == ("4MB", '"$user", public', 0, 0, None, 0)

    def test_the_same_query_planned_again_and_again(
        self, warehouse: Warehouse, engines: list[PostgresEngine]
    ) -> None:
        # EXPLAIN goes as a prepared statement; the reset drops it on the server, and psycopg
        # must forget it too, or the next one asks for a statement that is gone.
        engine = _pooled(engines, warehouse.public_dsn, size=1)
        for _ in range(12):
            assert engine.explain(SQL).total_cost > 0
            assert engine.execute(SQL).rows == ((7, "Product 7"),)

    def test_the_statement_timeout_holds_on_a_connection_lent_again(
        self, warehouse: Warehouse, engines: list[PostgresEngine]
    ) -> None:
        engine = _pooled(engines, warehouse.admin_dsn, size=1, statement_timeout_ms=300)
        for _ in range(3):
            started = time.monotonic()
            with pytest.raises(QueryTimeout):
                engine.execute("select pg_sleep(2)")
            assert time.monotonic() - started < 1.5
            assert engine.execute("select 1").rows == ((1,),)

    def test_every_transaction_is_read_only(
        self, warehouse: Warehouse, engines: list[PostgresEngine]
    ) -> None:
        # The engine takes only queries (it runs them through a cursor), so the write is
        # one a query makes: a large object.
        engine = _pooled(engines, warehouse.admin_dsn, size=1)
        before = _admin(warehouse, "SELECT count(*) FROM pg_largeobject_metadata")
        for _ in range(3):
            with pytest.raises(Exception, match="in a read-only transaction"):
                engine.execute("select lo_create(0)")
        assert _admin(warehouse, "SELECT count(*) FROM pg_largeobject_metadata") == before


class TestWhenThingsGoWrong:
    def test_a_connection_the_server_dropped_costs_no_request(
        self, warehouse: Warehouse, engines: list[PostgresEngine]
    ) -> None:
        engine = _pooled(engines, warehouse.public_dsn, size=2)
        assert engine.execute(SQL).rows
        killed = _admin(
            warehouse,
            "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
            "WHERE usename = 'warden_public'",
        )
        assert killed >= 1
        assert engine.execute(SQL).rows == ((7, "Product 7"),)

    def test_a_full_pool_answers_within_its_timeout(
        self, warehouse: Warehouse, engines: list[PostgresEngine]
    ) -> None:
        engine = _pooled(engines, warehouse.public_dsn, size=1, timeout_s=0.5)
        warden = Warden(engine, audit=MemoryAuditSink(), access=PRODUCTS)
        warden.run(SQL)  # the catalog, read
        pool = engine._pool
        assert pool is not None
        with pool.connection():  # held: nothing is left to lend
            started = time.monotonic()
            outcome = warden.run(SQL)
            took = time.monotonic() - started
        refused = outcome.decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert refused.refusal.code == RefusalCode.COST_UNAVAILABLE
        assert refused.refusal.reason.endswith(
            "no connection to the database was free within 0.5 s: every one is in use"
        )
        assert took < 2
        assert warden.run(SQL).result is not None  # and once it is back, all is well
        assert engine.pool_stats() is not None
        assert engine.pool_stats().timeouts == 1  # type: ignore[union-attr]

    def test_a_closed_pool_lends_nothing_and_leaves_nothing_open(
        self, warehouse: Warehouse, engines: list[PostgresEngine]
    ) -> None:
        engine = _pooled(engines, warehouse.public_dsn, size=3)
        _hammer(Warden(engine, audit=MemoryAuditSink(), access=PRODUCTS), threads=3, each=3)
        assert _open_as(warehouse, "warden_public") >= 1
        engine.close()
        with pytest.raises(EngineUnavailable, match="shutting down"):
            engine.execute(SQL)
        deadline = time.monotonic() + 5
        while _open_as(warehouse, "warden_public") and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _open_as(warehouse, "warden_public") == 0

    def test_a_retired_warden_closes_its_pool(
        self, warehouse: Warehouse, engines: list[PostgresEngine]
    ) -> None:
        metrics = Metrics()
        engine = _pooled(engines, warehouse.public_dsn)
        warden = Warden(
            engine, audit=MemoryAuditSink(), access=PRODUCTS, profile="public", metrics=metrics
        )
        warden.run(SQL)
        (line,) = [
            line
            for line in metrics.render().splitlines()
            if line.startswith('sql_warden_pool_connections{pool="warehouse",profile="public"}')
        ]
        assert int(line.split()[-1]) >= 1
        warden.close()  # what a reload does to the one it replaces
        assert "sql_warden_pool_connections{" not in metrics.render()
        with pytest.raises(EngineUnavailable):
            engine.execute(SQL)
