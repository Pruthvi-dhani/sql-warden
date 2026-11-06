import threading
import time
from dataclasses import dataclass, field

import pytest
import sqlglot
from sqlglot.errors import OptimizeError
from sqlglot.optimizer.qualify import qualify

from sql_warden.audit import MemoryAuditSink
from sql_warden.catalog import Catalog, column_type
from sql_warden.engines import Column, EngineUnavailable, Table
from sql_warden.warden import Warden
from tests.unit.conftest import PRODUCTS, FakeEngine

MIXED = Table("public", "MixedCase", (Column("Id", "integer"), Column("low", "text")))
REPORTS = Table("reports", "daily", (Column("day", "date"), Column("total", "numeric")))


@dataclass
class CountingEngine(FakeEngine):
    reads: int = 0
    failures: list[Exception] = field(default_factory=list)

    def tables(self) -> tuple[Table, ...]:
        self.reads += 1
        if self.failures:
            raise self.failures.pop(0)
        return self.catalog


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def engine() -> CountingEngine:
    return CountingEngine(catalog=(PRODUCTS, MIXED, REPORTS))


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def catalog(engine: CountingEngine, clock: Clock) -> Catalog:
    return Catalog(engine, max_age_s=60, clock=clock)


class TestCaching:
    def test_nothing_is_read_until_needed(self, engine: CountingEngine, catalog: Catalog) -> None:
        assert engine.reads == 0

    def test_one_read_serves_every_use_while_fresh(
        self, engine: CountingEngine, catalog: Catalog, clock: Clock
    ) -> None:
        catalog.tables()
        clock.now = 59.9
        catalog.schema()
        catalog.table("public", "products")
        assert engine.reads == 1

    def test_an_old_read_is_replaced(
        self, engine: CountingEngine, catalog: Catalog, clock: Clock
    ) -> None:
        catalog.tables()
        engine.catalog = (PRODUCTS,)
        clock.now = 60
        assert catalog.tables() == (PRODUCTS,)
        assert engine.reads == 2

    def test_refresh_forces_a_new_read(self, engine: CountingEngine, catalog: Catalog) -> None:
        catalog.tables()
        catalog.refresh()
        catalog.tables()
        assert engine.reads == 2

    def test_a_failed_read_is_not_cached(self, engine: CountingEngine, catalog: Catalog) -> None:
        engine.failures.append(EngineUnavailable("could not connect"))
        with pytest.raises(EngineUnavailable):
            catalog.tables()
        assert catalog.tables() == (PRODUCTS, MIXED, REPORTS)
        assert engine.reads == 2

    def test_concurrent_callers_share_one_read(self) -> None:
        class SlowEngine(CountingEngine):
            def tables(self) -> tuple[Table, ...]:
                time.sleep(0.05)
                return super().tables()

        engine = SlowEngine()
        catalog = Catalog(engine)
        threads = [threading.Thread(target=catalog.tables) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert engine.reads == 1

    def test_max_age_must_not_be_negative(self, engine: CountingEngine) -> None:
        with pytest.raises(ValueError, match="max_age_s"):
            Catalog(engine, max_age_s=-1)

    def test_the_warden_lists_tables_from_its_catalog(self, engine: CountingEngine) -> None:
        warden = Warden(engine, audit=MemoryAuditSink())
        assert warden.tables() == warden.tables() == (PRODUCTS, MIXED, REPORTS)
        assert engine.reads == 1


class TestLookup:
    def test_tables_are_found_by_exact_name(self, catalog: Catalog) -> None:
        assert catalog.table("public", "MixedCase") == MIXED
        assert catalog.table("reports", "daily") == REPORTS

    @pytest.mark.parametrize(
        ("schema", "name"),
        [("public", "mixedcase"), ("public", "Products"), ("reports", "products"), ("x", "y")],
    )
    def test_anything_else_is_not_there(self, catalog: Catalog, schema: str, name: str) -> None:
        assert catalog.table(schema, name) is None


class TestSchema:
    def test_columns_keep_their_order_and_case(self, catalog: Catalog) -> None:
        schema = catalog.schema()
        assert schema.column_names('public."MixedCase"') == ["Id", "low"]
        assert schema.column_names("public.products") == ["id", "name"]

    def test_types_are_read_as_sqlglot_types(self, catalog: Catalog) -> None:
        schema = catalog.schema()
        assert schema.get_column_type("reports.daily", "total").sql() == "DECIMAL"
        assert schema.get_column_type("reports.daily", "day").sql() == "DATE"

    @pytest.mark.parametrize(
        ("data_type", "expected"),
        [
            ("integer", "INT"),
            ("text", "TEXT"),
            ("timestamp with time zone", "TIMESTAMPTZ"),
            ("character varying", "VARCHAR"),
            ("double precision", "DOUBLE PRECISION"),
            ("jsonb", "JSONB"),
            ("ARRAY", "ARRAY"),
            ("tsvector", "UNKNOWN"),  # sqlglot can't parse it; the column is still listed
        ],
    )
    def test_column_type(self, data_type: str, expected: str) -> None:
        assert column_type(data_type, "postgres") == expected

    @pytest.mark.parametrize(
        ("sql", "expected"),
        [
            (
                "select * from products",
                'SELECT "products"."id" AS "id", "products"."name" AS "name" '
                'FROM "public"."products" AS "products"',
            ),
            # Unquoted names fold to lower case, as in Postgres.
            (
                "select ID from PRODUCTS",
                'SELECT "products"."id" AS "id" FROM "public"."products" AS "products"',
            ),
            # Quoted names keep their case.
            (
                'select * from "MixedCase"',
                'SELECT "mixedcase"."Id" AS "Id", "mixedcase"."low" AS "low" '
                'FROM "public"."MixedCase" AS "mixedcase"',
            ),
            (
                "select day from reports.daily",
                'SELECT "daily"."day" AS "day" FROM "reports"."daily" AS "daily"',
            ),
        ],
    )
    def test_qualify_resolves_names_like_postgres(
        self, catalog: Catalog, sql: str, expected: str
    ) -> None:
        assert _qualify(sql, catalog) == expected

    @pytest.mark.parametrize(
        "sql",
        ['select "ID" from products', "select nope from products", "select Id from mixedcase"],
    )
    def test_names_postgres_would_not_find_do_not_resolve(self, catalog: Catalog, sql: str) -> None:
        with pytest.raises(OptimizeError):
            _qualify(sql, catalog)


def _qualify(sql: str, catalog: Catalog) -> str:
    tree = qualify(
        sqlglot.parse_one(sql, dialect="postgres"),
        schema=catalog.schema(),
        dialect="postgres",
        db="public",
        validate_qualify_columns=True,
    )
    return tree.sql(dialect="postgres")
