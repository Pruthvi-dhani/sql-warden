from dataclasses import dataclass, field

import pytest

from sql_warden import cli as cli_module
from sql_warden.engines import EngineError, Result

ONE_ROW = Result(columns=("id",), rows=((1,),), truncated=False, duration_ms=1.0)


@dataclass
class FakeEngine:
    dsn: str = "fake://"
    statement_timeout_ms: int = 5_000
    max_rows: int = 100
    result: Result = ONE_ROW
    error: EngineError | None = None
    executed: list[str] = field(default_factory=list)

    def execute(self, sql: str) -> Result:
        self.executed.append(sql)
        if self.error is not None:
            raise self.error
        return self.result


@pytest.fixture
def engines(monkeypatch: pytest.MonkeyPatch) -> list[FakeEngine]:
    """Replace PostgresEngine in the CLI and collect every engine it builds."""
    built: list[FakeEngine] = []

    def factory(dsn: str, *, statement_timeout_ms: int, max_rows: int) -> FakeEngine:
        engine = FakeEngine(dsn, statement_timeout_ms, max_rows)
        built.append(engine)
        return engine

    monkeypatch.setattr(cli_module, "PostgresEngine", factory)
    monkeypatch.delenv("SQL_WARDEN_DSN", raising=False)
    return built
