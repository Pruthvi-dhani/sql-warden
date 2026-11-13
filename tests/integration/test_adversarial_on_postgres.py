"""Hostile queries against a real Postgres, as its superuser: the worst role there is.

tests/unit/test_adversarial.py pins what the checks refuse. This is what holds when they are
not there at all (the engine is handed the hostile text itself), what Postgres makes of the
queries the checks let through rewritten, and that the questions the checks refuse to pass on
are ones Postgres would have answered.
"""

from collections.abc import Iterator
from contextlib import suppress

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from sql_warden.audit import MemoryAuditSink, PostgresAuditSink
from sql_warden.engines import EngineError
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.models import RefusalCode
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration

STATE = """
    SELECT (SELECT count(*) FROM products),
           (SELECT count(*) FROM customers),
           (SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace),
           (SELECT count(*) FROM pg_largeobject_metadata),
           (SELECT count(*) FROM pg_roles)
"""


def _state(warehouse: Warehouse) -> tuple[int, ...]:
    with psycopg.connect(warehouse.admin_dsn) as conn:
        row = conn.execute(STATE).fetchone()
    assert row is not None
    return tuple(row)


@pytest.fixture
def untouched(warehouse: Warehouse) -> Iterator[None]:
    """Fails the test if anything in the warehouse is different after it."""
    before = _state(warehouse)
    yield
    assert _state(warehouse) == before


WRITES = [
    "DELETE FROM products",
    "UPDATE products SET name = 'x'",
    "INSERT INTO products SELECT * FROM products",
    "TRUNCATE products",
    "DROP TABLE products",
    "CREATE TABLE loot (a int)",
    "CREATE ROLE intruder SUPERUSER",
    "SELECT 1; DELETE FROM products",
    "SELECT 1; COMMIT; DELETE FROM products",
    "WITH gone AS (DELETE FROM products RETURNING *) SELECT * FROM gone",
    "SELECT * INTO loot FROM products",
    "SELECT * FROM products FOR UPDATE",
    "DO $$ BEGIN DELETE FROM products; END $$",
    "COPY products TO '/tmp/loot'",
    "COPY products FROM PROGRAM 'true'",
    "EXPLAIN ANALYZE DELETE FROM products",
    "ANALYZE DELETE FROM products",
    "SELECT lo_create(0)",
    "COMMIT",
    "SET TRANSACTION READ WRITE",
    "SELECT set_config('transaction_read_only', 'off', true)",
]


class TestTheEngineAlone:
    """No checks: the text goes straight to the engine, connected as the superuser. The
    read-only transaction and the one statement the engine sends are all that is left."""

    @pytest.mark.parametrize("sql", WRITES)
    def test_nothing_that_writes_runs(
        self, warehouse: Warehouse, untouched: None, sql: str
    ) -> None:
        with pytest.raises(EngineError):
            PostgresEngine(warehouse.admin_dsn).execute(sql)

    @pytest.mark.parametrize("sql", WRITES)
    def test_nor_does_planning_it_run_it(
        self, warehouse: Warehouse, untouched: None, sql: str
    ) -> None:
        # EXPLAIN of a write only plans it, and a second statement after it is refused.
        with suppress(EngineError):
            PostgresEngine(warehouse.admin_dsn).explain(sql)

    def test_a_setting_changed_by_a_query_is_gone_with_its_transaction(
        self, warehouse: Warehouse
    ) -> None:
        engine = PostgresEngine(warehouse.admin_dsn, statement_timeout_ms=1_000)
        engine.execute("SELECT set_config('statement_timeout', '0', false)")
        timeout = engine.execute("SELECT current_setting('statement_timeout')")
        assert timeout.rows == (("1s",),)


def _warden(warehouse: Warehouse) -> Warden:
    return Warden(PostgresEngine(warehouse.admin_dsn), audit=MemoryAuditSink())


class TestWhatTheChecksLetThrough:
    """Rewritten, these run. Postgres reads each as one harmless SELECT, and what comes back
    is the string that was sent, not what the string says to do."""

    @pytest.mark.parametrize(
        ("sql", "columns", "row"),
        [
            ("select 1 as n -- ; delete from products", ("n",), (1,)),
            ("select 1 as n /* ; delete from products */", ("n",), (1,)),
            ("select $x$; delete from products$x$ as s", ("s",), ("; delete from products",)),
            (
                r"select E'a\'; drop table products; --' as s",
                ("s",),
                ("a'; drop table products; --",),
            ),
            (
                r"select E'\x27; drop table products; --' as s",
                ("s",),
                ("'; drop table products; --",),
            ),
            (
                'select 1 as "x"";delete from products;--"',
                ('x";delete from products;--',),
                (1,),
            ),
            ("select ' /* ' as a, ' */ ' as b", ("a", "b"), (" /* ", " */ ")),
            ("select '--' as a, 2 as b", ("a", "b"), ("--", 2)),
            (r"select 'a\' as a, 'b' as b", ("a", "b"), ("a\\", "b")),
        ],
    )
    def test_postgres_reads_them_as_the_checks_did(
        self,
        warehouse: Warehouse,
        untouched: None,
        sql: str,
        columns: tuple[str, ...],
        row: tuple[object, ...],
    ) -> None:
        outcome = _warden(warehouse).run(sql)
        assert outcome.result is not None, outcome.decision.refused_by or outcome.error
        assert (outcome.result.columns, outcome.result.rows) == (columns, (row,))

    @pytest.mark.parametrize(
        "sql",
        [
            "select 1; delete from products",
            r"select 'a\'; delete from products; --'",
            "with gone as (delete from products returning *) select * from gone",
            "select set_config('default_transaction_read_only', 'off', false)",
            "select lo_create(0)",
            "copy products to '/tmp/loot'",
        ],
    )
    def test_and_what_they_refuse_never_arrives(
        self, warehouse: Warehouse, untouched: None, sql: str
    ) -> None:
        outcome = _warden(warehouse).run(sql)
        assert outcome.result is None
        assert not outcome.decision.allowed

    @pytest.mark.parametrize(
        "sql", ["select $1", "select :x", "select ?", "select %s", "select %(x)s"]
    )
    def test_a_placeholder_is_an_error_not_a_way_in(
        self, warehouse: Warehouse, untouched: None, sql: str
    ) -> None:
        # Nothing fills it in, here or in the driver: Postgres is asked, and says no.
        outcome = _warden(warehouse).run(sql)
        assert outcome.result is None
        refused = outcome.decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert refused.refusal.code in {RefusalCode.PLAN_FAILED, RefusalCode.PARSE_ERROR}


class TestStringsAreReadTheStandardWay:
    """The checks read a backslash in '...' as a backslash, as Postgres does by default. A
    server or a role can be set to the old way, where it escapes the next character and the
    string ends somewhere else. The engine sets the standard way for every query."""

    @pytest.fixture
    def legacy_dsn(self, warehouse: Warehouse) -> Iterator[str]:
        with psycopg.connect(warehouse.admin_dsn, autocommit=True) as conn:
            conn.execute("CREATE ROLE adv_legacy LOGIN PASSWORD 'adv_legacy'")
            conn.execute("ALTER ROLE adv_legacy SET standard_conforming_strings = off")
        try:
            yield make_conninfo(warehouse.reader_dsn, user="adv_legacy", password="adv_legacy")
        finally:
            with psycopg.connect(warehouse.admin_dsn, autocommit=True) as conn:
                conn.execute("DROP ROLE adv_legacy")

    def test_whatever_the_role_is_set_to(self, legacy_dsn: str) -> None:
        text = r"SELECT 'a\' AS a, 'b' AS b"
        with psycopg.connect(legacy_dsn) as conn:
            assert conn.execute("SHOW standard_conforming_strings").fetchone() == ("off",)
            with pytest.raises(psycopg.Error):  # read the old way, it is not even a query
                conn.execute(text)
        result = PostgresEngine(legacy_dsn).execute(text)
        assert result.rows == (("a\\", "b"),)
        assert PostgresEngine(legacy_dsn).explain(text).total_cost >= 0


class TestWhatACastWouldHaveTold:
    """warden_public can read three columns of products. Postgres itself still tells it
    which tables exist and what their columns are called, to anyone who asks with a cast.
    That is why the checks refuse to pass the question on."""

    def test_postgres_answers(self, warehouse: Warehouse) -> None:
        engine = PostgresEngine(warehouse.public_dsn)
        assert engine.execute("SELECT 'employee_salaries'::regclass::text").rows == (
            ("employee_salaries",),
        )
        with pytest.raises(EngineError, match="does not exist"):
            engine.execute("SELECT 'no_such_table'::regclass")
        hidden = engine.execute("SELECT (NULL::employee_salaries).*")
        assert {"id", "salary_cents"} <= set(hidden.columns)
        assert "category" in engine.execute("SELECT (NULL::products).*").columns

    @pytest.mark.parametrize(
        "sql",
        [
            "select 'employee_salaries'::regclass::text",
            "select 'no_such_table'::regclass",
            "select (null::employee_salaries).*",
            "select (null::products).*",
        ],
    )
    def test_the_checks_dont_ask(self, warehouse: Warehouse, sql: str) -> None:
        warden = Warden(PostgresEngine(warehouse.public_dsn), audit=MemoryAuditSink())
        refused = warden.run(sql).decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert refused.refusal.code == RefusalCode.TYPE_NOT_ALLOWED


class TestTheAuditLogTakesWhatIsSent:
    @pytest.fixture
    def sink(self, audit_dsn: str) -> Iterator[PostgresAuditSink]:
        sink = PostgresAuditSink(audit_dsn)
        sink.ensure_schema()
        yield sink
        sink.close()

    def _recorded(self, audit_dsn: str, audit_id: object) -> str:
        with psycopg.connect(audit_dsn) as conn:
            row = conn.execute("SELECT sql FROM audit_events WHERE id = %s", (audit_id,)).fetchone()
        assert row is not None
        return str(row[0])

    @pytest.mark.parametrize(
        ("sql", "recorded"),
        [
            ("select 'a\x00b'", "select 'a\\x00b'"),
            ("select '\ud800'", "select '\\ud800'"),
        ],
    )
    def test_text_postgres_cant_store_is_recorded_escaped(
        self, warehouse: Warehouse, sink: PostgresAuditSink, audit_dsn: str, sql: str, recorded: str
    ) -> None:
        warden = Warden(PostgresEngine(warehouse.reader_dsn), audit=sink)
        decision = warden.run(sql).decision
        refused = decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        # Refused for what it is, and on the record: not lost to a failed audit write.
        assert (refused.check, refused.refusal.code) == ("parse", RefusalCode.PARSE_ERROR)
        assert decision.audit_id is not None
        assert self._recorded(audit_dsn, decision.audit_id) == recorded

    def test_a_query_of_megabytes_is_recorded_cut_short(
        self, warehouse: Warehouse, sink: PostgresAuditSink, audit_dsn: str
    ) -> None:
        warden = Warden(PostgresEngine(warehouse.reader_dsn), audit=sink)
        decision = warden.run("select 1 /*" + "x" * 3_000_000 + "*/").decision
        assert decision.audit_id is not None
        recorded = self._recorded(audit_dsn, decision.audit_id)
        assert len(recorded) < 2_100
        assert recorded.endswith("(3,000,013 characters; the first 2,000 are recorded)")
