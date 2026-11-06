import dataclasses
import datetime
import threading

import pytest

from sql_warden.audit import AuditError, AuditEvent, AuditSink, MemoryAuditSink, PostgresAuditSink
from sql_warden.audit.sink import SCHEMA


def _event(sql: str = "select 1") -> AuditEvent:
    return AuditEvent(profile="all", sql=sql, decision="allowed", duration_ms=1.0)


class TestEvent:
    def test_each_event_gets_its_own_id(self) -> None:
        assert _event().id != _event().id

    def test_timestamps_are_utc(self) -> None:
        before = datetime.datetime.now(datetime.UTC)
        event = _event()
        assert event.ts.tzinfo is datetime.UTC
        assert before <= event.ts <= datetime.datetime.now(datetime.UTC)

    def test_events_cannot_be_changed_once_made(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            _event().sql = "select 2"  # type: ignore[misc]


class TestMemorySink:
    def test_keeps_events_in_order(self) -> None:
        sink = MemoryAuditSink()
        first, second = _event("select 1"), _event("select 2")
        sink.record(first)
        sink.record(second)
        assert sink.events == (first, second)

    def test_can_be_made_to_fail(self) -> None:
        sink = MemoryAuditSink()
        sink.fail_with = AuditError("could not record the audit event: connection refused")
        with pytest.raises(AuditError, match="connection refused"):
            sink.record(_event())
        assert sink.events == ()

    def test_threads_can_share_it(self) -> None:
        sink = MemoryAuditSink()

        def write() -> None:
            for _ in range(100):
                sink.record(_event())

        threads = [threading.Thread(target=write) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(sink.events) == 800


def test_both_sinks_are_audit_sinks() -> None:
    sinks: list[AuditSink] = [MemoryAuditSink(), PostgresAuditSink("postgresql://unused/db")]
    assert len(sinks) == 2


def test_the_schema_ships_with_the_package() -> None:
    schema = SCHEMA.read_text()
    assert "CREATE TABLE IF NOT EXISTS audit_events" in schema
    # Every column an event has is in the table.
    for field in dataclasses.fields(AuditEvent):
        assert f"\n    {field.name} " in schema, field.name
