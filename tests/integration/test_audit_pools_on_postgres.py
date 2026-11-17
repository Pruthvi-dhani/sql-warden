"""The audit log's and the budgets' connection pools, against real Postgres: records written
side by side, each exactly once; a full pool refused before the warehouse is asked; and
connections the audit database dropped, idle or in the middle of a request."""

import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import psycopg
import pytest

from sql_warden.audit import AuditEvent, PostgresAuditSink
from sql_warden.config import BudgetConfig
from sql_warden.models import QueryOutcome, RefusalCode
from sql_warden.pools import PoolSettings
from sql_warden.sessions import Usage
from sql_warden.warden import NOT_COUNTED, Warden
from tests.unit.conftest import FakeEngine

pytestmark = pytest.mark.integration

SQL = "select id from products"


@pytest.fixture
def fresh(audit_dsn: str) -> None:
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS audit_events, session_usage, caller_charges")
    sink = PostgresAuditSink(audit_dsn)
    sink.ensure_schema()
    sink.close()


@pytest.fixture
def sinks() -> Iterator[list[PostgresAuditSink]]:
    """Every pooled sink a test makes, closed after it."""
    made: list[PostgresAuditSink] = []
    yield made
    for sink in made:
        sink.close()


def _pooled(
    sinks: list[PostgresAuditSink], dsn: str, size: int = 4, **settings: Any
) -> PostgresAuditSink:
    sink = PostgresAuditSink(dsn, pool=PoolSettings(max_size=size, **settings))
    sinks.append(sink)
    return sink


def _scalar(audit_dsn: str, sql: str, params: Any = None) -> Any:
    with psycopg.connect(audit_dsn, autocommit=True) as conn:
        row = conn.execute(sql, params).fetchone()
    assert row is not None
    return row[0]


# Every other client's connection to the audit database: the sink's, since tests run one at
# a time. What a restart of the database does to them, without the wait for it to come back.
_OTHERS = (
    "FROM pg_stat_activity WHERE datname = current_database() "
    "AND backend_type = 'client backend' AND pid <> pg_backend_pid()"
)


def _connected(audit_dsn: str) -> int:
    return int(_scalar(audit_dsn, f"SELECT count(*) {_OTHERS}"))


def _drop_connections(audit_dsn: str) -> int:
    return int(_scalar(audit_dsn, f"SELECT count(pg_terminate_backend(pid)) {_OTHERS}"))


def _event(n: int) -> AuditEvent:
    return AuditEvent(
        profile="support", sql=f"select {n}", decision="allowed", duration_ms=1.0, session_id="s"
    )


class _Held:
    """Keeps one connection of a pool lent out, as a slow request would, until released."""

    def __init__(self, attempt: Callable[..., Any]) -> None:
        self._lent, self._release = threading.Event(), threading.Event()

        def hold(conn: psycopg.Connection[Any]) -> None:
            self._lent.set()
            self._release.wait(10)

        self._thread = threading.Thread(target=attempt, args=(hold, "held", RuntimeError))
        self._thread.start()
        assert self._lent.wait(5)

    def release(self) -> None:
        self._release.set()
        self._thread.join()


def _code(outcome: QueryOutcome) -> RefusalCode | None:
    refused = outcome.decision.refused_by
    return None if refused is None or refused.refusal is None else refused.refusal.code


class TestRecords:
    def test_from_16_threads_are_all_written_each_once(
        self, fresh: None, audit_dsn: str, sinks: list[PostgresAuditSink]
    ) -> None:
        sink = _pooled(sinks, audit_dsn, size=4)
        events = [_event(n) for n in range(16 * 25)]
        start = threading.Barrier(16)
        most = 0

        def write(mine: list[AuditEvent]) -> None:
            nonlocal most
            start.wait()
            for event in mine:
                sink.record(event)
                stats = sink.pool_stats()["audit"]
                assert stats is not None
                most = max(most, stats.open)

        workers = [threading.Thread(target=write, args=(events[n::16],)) for n in range(16)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        assert _scalar(audit_dsn, "SELECT count(*) FROM audit_events") == 400
        written = _scalar(audit_dsn, "SELECT array_agg(id) FROM audit_events")
        assert sorted(written) == sorted(event.id for event in events)
        assert 1 <= most <= 4

    def test_are_written_side_by_side_not_one_after_another(
        self, fresh: None, audit_dsn: str, sinks: list[PostgresAuditSink]
    ) -> None:
        sink = _pooled(sinks, audit_dsn, size=2)
        held = _Held(sink._records.attempt)  # one connection busy for as long as it likes
        try:
            started = time.monotonic()
            sink.record(_event(1))  # on the other: it doesn't wait for the first
            assert time.monotonic() - started < 2
        finally:
            held.release()
        assert _scalar(audit_dsn, "SELECT count(*) FROM audit_events") == 1


class TestAFullPool:
    def test_of_records_refuses_the_query_before_the_warehouse_is_asked(
        self, fresh: None, audit_dsn: str, sinks: list[PostgresAuditSink]
    ) -> None:
        sink = _pooled(sinks, audit_dsn, size=1, timeout_s=0.3)
        engine = FakeEngine()
        warden = Warden(engine, audit=sink)
        held = _Held(sink._records.attempt)
        try:
            started = time.monotonic()
            outcome = warden.run(SQL)
            assert time.monotonic() - started < 2
        finally:
            held.release()
        assert _code(outcome) == RefusalCode.AUDIT_UNAVAILABLE
        refused = outcome.decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert "no connection to the audit database was free within 0.3 s" in (
            refused.refusal.reason
        )
        assert outcome.result is None
        assert engine.executed == []  # nothing ran without a record to show for it
        stats = sink.pool_stats()["audit"]
        assert stats is not None
        assert stats.timeouts == 1
        # Once the connection is back, the next request is answered and recorded.
        again = warden.run(SQL)
        assert again.result is not None
        assert _scalar(audit_dsn, "SELECT count(*) FROM audit_events") == 1

    def test_of_budgets_refuses_the_charge_but_not_the_record(
        self, fresh: None, audit_dsn: str, sinks: list[PostgresAuditSink]
    ) -> None:
        sink = _pooled(sinks, audit_dsn, size=1, timeout_s=0.3)
        store = sink.session_store("support", not_counted=NOT_COUNTED)
        engine = FakeEngine()
        warden = Warden(
            engine,
            audit=sink,
            profile="support",
            budget=BudgetConfig(max_queries=5),
            sessions=store,
        )
        assert sink._budgets is not None
        held = _Held(sink._budgets.attempt)  # every budget connection busy
        try:
            outcome = warden.run(SQL, session_id="s")
        finally:
            held.release()
        assert _code(outcome) == RefusalCode.BUDGET_UNAVAILABLE
        assert engine.executed == []
        # The records have connections of their own, so the refusal is on the record.
        recorded = "SELECT code FROM audit_events WHERE decision = 'refused'"
        assert _scalar(audit_dsn, recorded) == "BUDGET_UNAVAILABLE"


class TestDroppedConnections:
    def _warden(self, sinks: list[PostgresAuditSink], audit_dsn: str) -> Warden:
        sink = _pooled(sinks, audit_dsn, size=4)
        return Warden(
            FakeEngine(),
            audit=sink,
            profile="support",
            budget=BudgetConfig(max_queries=10_000),
            sessions=sink.session_store("support", not_counted=NOT_COUNTED),
        )

    def test_idle_ones_cost_no_request(
        self, fresh: None, audit_dsn: str, sinks: list[PostgresAuditSink]
    ) -> None:
        warden = self._warden(sinks, audit_dsn)
        assert warden.run(SQL, session_id="s").result is not None
        assert _drop_connections(audit_dsn) >= 2  # a record's and a charge's, at least
        outcomes = [warden.run(SQL, session_id="s") for _ in range(5)]
        assert [_code(outcome) for outcome in outcomes] == [None] * 5

    def test_under_load_cost_at_most_the_requests_in_flight(
        self, fresh: None, audit_dsn: str, sinks: list[PostgresAuditSink]
    ) -> None:
        warden = self._warden(sinks, audit_dsn)
        outcomes: list[QueryOutcome] = []
        lock = threading.Lock()

        def ask(n: int) -> None:
            for i in range(40):
                outcome = warden.run(SQL, session_id=f"s{n}-{i % 4}")
                with lock:
                    outcomes.append(outcome)

        workers = [threading.Thread(target=ask, args=(n,)) for n in range(8)]
        for worker in workers:
            worker.start()
        drops = 0
        while drops < 3:
            time.sleep(0.15)
            drops += _drop_connections(audit_dsn) > 0
        for worker in workers:
            worker.join()
        assert len(outcomes) == 320
        lost = [o for o in outcomes if o.result is None]
        # Each one lost was refused for the reason it was, and no more were lost than were
        # being answered (8 threads) each time the connections dropped.
        assert {_code(o) for o in lost} <= {
            RefusalCode.AUDIT_UNAVAILABLE,
            RefusalCode.BUDGET_UNAVAILABLE,
        }
        assert len(lost) <= 3 * 8
        # Everything that came back is on the record, once.
        answered = [str(o.decision.audit_id) for o in outcomes if o.result is not None]
        found = _scalar(
            audit_dsn,
            "SELECT count(*) FROM audit_events WHERE id = ANY(%s::uuid[])",
            (answered,),
        )
        assert found == len(answered)
        assert warden.run(SQL, session_id="after").result is not None


def test_a_closed_sink_leaves_nothing_open(
    fresh: None, audit_dsn: str, sinks: list[PostgresAuditSink]
) -> None:
    sink = _pooled(sinks, audit_dsn, size=3)
    store = sink.session_store("support")
    sink.record(_event(1))
    store.charge("s", Usage(queries=1))
    assert _connected(audit_dsn) >= 2
    store.close()  # a reload retiring a Warden: the budgets' pool is the sink's, and stays
    sink.record(_event(2))
    sink.close()
    deadline = time.monotonic() + 3
    while _connected(audit_dsn) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert _connected(audit_dsn) == 0
