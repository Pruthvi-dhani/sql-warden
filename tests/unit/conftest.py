from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sql_warden import cli as cli_module
from sql_warden.engines import Column, EngineError, Result, Table

ONE_ROW = Result(columns=("id",), rows=((1,),), truncated=False, duration_ms=1.0)
PRODUCTS = Table("public", "products", (Column("id", "integer"), Column("name", "text")))


@dataclass
class FakeEngine:
    dsn: str = "fake://"
    statement_timeout_ms: int = 5_000
    max_rows: int = 100
    connect_timeout_s: int = 5
    result: Result = ONE_ROW
    error: EngineError | None = None
    catalog: tuple[Table, ...] = (PRODUCTS,)
    executed: list[str] = field(default_factory=list)

    def execute(self, sql: str) -> Result:
        self.executed.append(sql)
        if self.error is not None:
            raise self.error
        return self.result

    def tables(self) -> tuple[Table, ...]:
        if self.error is not None:
            raise self.error
        return self.catalog


@pytest.fixture(autouse=True)
def isolated_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Run every unit test in an empty directory with no sql-warden env vars, so a local
    warden.yaml or SQL_WARDEN_* variable can never change what a test sees."""
    monkeypatch.chdir(tmp_path)
    for name in ("SQL_WARDEN_CONFIG", "SQL_WARDEN_DSN"):
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
