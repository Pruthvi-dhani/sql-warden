from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sql_warden import cli as cli_module
from sql_warden.audit import AuditError, AuditEvent, MemoryAuditSink
from sql_warden.engines import Column, CostEstimate, EngineError, Result, Table

ONE_ROW = Result(columns=("id",), rows=((1,),), truncated=False, duration_ms=1.0)
PRODUCTS = Table("public", "products", (Column("id", "integer"), Column("name", "text")))
CHEAP = CostEstimate(total_cost=1.0, est_rows=1, top_node="Result")


@dataclass
class FakeEngine:
    dsn: str = "fake://"
    statement_timeout_ms: int = 5_000
    max_rows: int = 100
    connect_timeout_s: int = 5
    result: Result = ONE_ROW
    error: EngineError | None = None
    catalog: tuple[Table, ...] = (PRODUCTS,)
    estimate: CostEstimate = CHEAP
    explain_error: EngineError | None = None
    """Raised by explain(); error is for execute() and tables()."""
    executed: list[str] = field(default_factory=list)
    explained: list[str] = field(default_factory=list)

    def execute(self, sql: str) -> Result:
        self.executed.append(sql)
        if self.error is not None:
            raise self.error
        return self.result

    def tables(self) -> tuple[Table, ...]:
        if self.error is not None:
            raise self.error
        return self.catalog

    def explain(self, sql: str) -> CostEstimate:
        self.explained.append(sql)
        if self.explain_error is not None:
            raise self.explain_error
        return self.estimate


@pytest.fixture(autouse=True)
def isolated_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Run every unit test in an empty directory with no sql-warden env vars, so a local
    warden.yaml or SQL_WARDEN_* variable can never change what a test sees."""
    monkeypatch.chdir(tmp_path)
    for name in ("SQL_WARDEN_CONFIG", "SQL_WARDEN_DSN", "SQL_WARDEN_AUDIT_DSN"):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


@pytest.fixture
def engines(monkeypatch: pytest.MonkeyPatch) -> list[FakeEngine]:
    """Replace PostgresEngine in the CLI and collect every engine it builds."""
    built: list[FakeEngine] = []

    def factory(
        dsn: str, *, statement_timeout_ms: int, max_rows: int, connect_timeout_s: int
    ) -> FakeEngine:
        engine = FakeEngine(dsn, statement_timeout_ms, max_rows, connect_timeout_s)
        built.append(engine)
        return engine

    monkeypatch.setattr(cli_module, "PostgresEngine", factory)
    return built


class FakeAuditSink(MemoryAuditSink):
    """What the CLI gets instead of PostgresAuditSink: events in a list."""

    def __init__(self, dsn: str, *, connect_timeout_s: int) -> None:
        super().__init__()
        self.dsn = dsn
        self.connect_timeout_s = connect_timeout_s
        self.schema_applied = False

    def ensure_schema(self) -> None:
        self.ping()
        self.schema_applied = True


@dataclass
class AuditSinks:
    built: list[FakeAuditSink] = field(default_factory=list)
    fail_with: AuditError | None = None
    """Set to make the sinks built from now on fail, as an unreachable database would."""

    @property
    def events(self) -> list[AuditEvent]:
        return [event for sink in self.built for event in sink.events]


@pytest.fixture(autouse=True)
def audit_sinks(monkeypatch: pytest.MonkeyPatch) -> AuditSinks:
    """Replace PostgresAuditSink in the CLI, so no unit test needs an audit database."""
    sinks = AuditSinks()

    def factory(dsn: str, *, connect_timeout_s: int) -> FakeAuditSink:
        sink = FakeAuditSink(dsn, connect_timeout_s=connect_timeout_s)
        sink.fail_with = sinks.fail_with
        sinks.built.append(sink)
        return sink

    monkeypatch.setattr(cli_module, "PostgresAuditSink", factory)
    return sinks
