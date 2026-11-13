"""SnowflakeEngine against a stand-in for Snowflake's connector: what it sends, and what it
makes of what comes back. No account, and no fakesnow: tests/fakesnow runs real SQL."""

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from snowflake.connector import errors

from sql_warden import cli as cli_module
from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import EXIT_REFUSED, cli
from sql_warden.config import (
    SNOWFLAKE_MAX_TOTAL_COST,
    BudgetConfig,
    ConfigError,
    CostConfig,
    MaskRule,
    describe_dsn,
    parse_config,
)
from sql_warden.engines import (
    EngineError,
    EngineUnavailable,
    QueryFailed,
    QueryTimeout,
    RoleReport,
)
from sql_warden.engines.snowflake import (
    SnowflakeDsn,
    SnowflakeEngine,
    cost_estimate,
    describe_operation,
    format_bytes,
)
from sql_warden.models import Decision
from sql_warden.profiles import Access
from sql_warden.warden import Warden
from tests.unit.conftest import AuditSinks

SESSION_SETUP = "USE SECONDARY ROLES NONE"
DSN = "snowflake://WARDEN_READER:s3cret@myorg-acct/warehouse/public?warehouse=XS&role=READER"
PLANS = Path(__file__).parent / "fixtures" / "snowflake_explain"
COMPILE_ERROR = errors.ProgrammingError(
    msg="SQL compilation error:\nObject 'NOSUCH' does not exist or not authorized.",
    errno=2003,
    sqlstate="42S02",
)
TIMED_OUT = errors.ProgrammingError(
    msg="Statement reached its statement or warehouse timeout of 5 second(s) and was canceled.",
    errno=630,
    sqlstate="57014",
)
LOST = errors.OperationalError(msg="Connection reset by peer", errno=251011)
EXPIRED = errors.DatabaseError(
    msg="Authentication token has expired. The user must authenticate again.",
    errno=390114,
    sqlstate="08001",
)


def _plan(name: str) -> dict[str, Any]:
    plan: dict[str, Any] = json.loads((PLANS / f"{name}.json").read_text())
    return plan


@dataclass
class Column:
    name: str


@dataclass
class Rows:
    """What a statement returns."""

    columns: tuple[str, ...] = ()
    rows: list[tuple[Any, ...]] = field(default_factory=list)


@dataclass
class FakeCursor:
    connection: "FakeConnection"
    answer: Rows = field(default_factory=Rows)
    fetch_sizes: list[int] = field(default_factory=list)
    closed: bool = False

    @property
    def description(self) -> list[Column]:
        return [Column(name) for name in self.answer.columns]

    def execute(self, operation: str, **options: Any) -> "FakeCursor":
        snow = self.connection.snow
        if operation == SESSION_SETUP:  # kept apart: it is no answer to any request
            self.connection.setup.append(operation)
            if snow.refuse_setup is not None:
                raise snow.refuse_setup
            return self
        snow.statements.append((operation, options))
        answer = snow.answers.pop(0) if snow.answers else snow.default
        if isinstance(answer, BaseException):
            raise answer
        self.answer = answer
        return self

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        self.fetch_sizes.append(size)
        return self.answer.rows[:size]

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.answer.rows[0] if self.answer.rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self.answer.rows)

    def close(self) -> None:
        self.closed = True


@dataclass
class FakeConnection:
    snow: "FakeSnowflake"
    cursors: list[FakeCursor] = field(default_factory=list)
    setup: list[str] = field(default_factory=list)
    """What the engine ran to set the session up, before anything in `statements`."""
    closed: bool = False

    def cursor(self) -> FakeCursor:
        cursor = FakeCursor(self)
        self.cursors.append(cursor)
        return cursor

    def close(self) -> None:
        self.closed = True


@dataclass
class FakeSnowflake:
    """Stands in for snowflake.connector.connect: answers statements from a queue, then with
    `default`. An answer that is an exception is raised."""

    answers: list[Rows | BaseException] = field(default_factory=list)
    default: Rows = field(default_factory=lambda: Rows(("ID",), [(1,), (2,), (3,)]))
    refuse: BaseException | None = None
    """Raised by every connect()."""
    refuse_setup: BaseException | None = None
    """Raised when a new session is set up."""
    connected: list[dict[str, Any]] = field(default_factory=list)
    connections: list[FakeConnection] = field(default_factory=list)
    statements: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def __call__(self, **settings: Any) -> FakeConnection:
        self.connected.append(settings)
        if self.refuse is not None:
            raise self.refuse
        connection = FakeConnection(self)
        self.connections.append(connection)
        return connection

    @property
    def sql(self) -> list[str]:
        return [statement for statement, _ in self.statements]


def _engine(snow: FakeSnowflake | None = None, **settings: Any) -> SnowflakeEngine:
    return SnowflakeEngine(DSN, connect=snow or FakeSnowflake(), **settings)


class TestDsn:
    def test_a_full_connection_string(self) -> None:
        assert SnowflakeDsn.parse(DSN) == SnowflakeDsn(
            account="myorg-acct",
            user="WARDEN_READER",
            password="s3cret",
            database="WAREHOUSE",
            schema="PUBLIC",
            warehouse="XS",
            role="READER",
        )

    def test_the_schema_is_public_unless_named_and_names_are_stored_upper_case(self) -> None:
        assert SnowflakeDsn.parse("snowflake://u@acct/sales").schema == "PUBLIC"
        named = SnowflakeDsn.parse("snowflake://u@acct/sales/reporting")
        assert (named.database, named.schema) == ("SALES", "REPORTING")

    def test_a_key_pair_instead_of_a_password(self) -> None:
        dsn = SnowflakeDsn.parse(
            "snowflake://svc@acct/db?private_key_file=/run/secrets/key.p8"
            "&private_key_file_pwd=k3y&authenticator=SNOWFLAKE_JWT"
        )
        assert dsn.password is None
        assert dsn.connect_args() == {
            "account": "acct",
            "user": "svc",
            "database": "DB",
            "schema": "PUBLIC",
            "authenticator": "SNOWFLAKE_JWT",
            "private_key_file": "/run/secrets/key.p8",
            "private_key_file_pwd": "k3y",
        }

    def test_characters_a_url_cant_hold_are_percent_encoded(self) -> None:
        dsn = SnowflakeDsn.parse("snowflake://first.last%40example.com:p%40ss%2Fw%3Ard@acct/db")
        assert (dsn.user, dsn.password) == ("first.last@example.com", "p@ss/w:rd")

    @pytest.mark.parametrize(
        ("dsn", "problem"),
        [
            ("postgresql://u:hunter2@host/db", "starts with snowflake://"),
            ("snowflake://acct/db", "needs a user and an account"),
            ("snowflake://u:hunter2@/db", "needs a user and an account"),
            ("snowflake://u:hunter2@acct:443/db", "names an account, not a host and port"),
            ("snowflake://u:hunter2@acct", "needs the database"),
            ("snowflake://u:hunter2@acct/db/schema/table", "needs the database"),
            ("snowflake://u:hunter2@acct/db?warehose=XS", "unknown connection option warehose"),
            ("snowflake://u:hunter2@acct/db?a=1&b=2", "unknown connection options a, b"),
            ("snowflake://u:hunter2@acct:port/db", "not a Snowflake connection string"),
        ],
    )
    def test_what_it_cant_be_and_never_the_password(self, dsn: str, problem: str) -> None:
        with pytest.raises(ValueError, match=problem) as excinfo:
            SnowflakeDsn.parse(dsn)
        assert "hunter2" not in str(excinfo.value)

    def test_it_is_shown_without_the_password(self) -> None:
        parsed = SnowflakeDsn.parse(DSN)
        assert parsed.describe() == (
            "myorg-acct/WAREHOUSE/PUBLIC as WARDEN_READER (role READER, warehouse XS)"
        )
        assert SnowflakeDsn.parse("snowflake://u:pw@acct/db").describe() == "acct/DB/PUBLIC as u"
        assert "s3cret" not in repr(parsed)
        assert describe_dsn(DSN) == parsed.describe()
        assert describe_dsn("snowflake://u:pw@acct") == "(unparseable connection string)"


class TestConnecting:
    def test_nothing_connects_until_something_is_asked(self) -> None:
        snow = FakeSnowflake()
        engine = _engine(snow)
        assert snow.connected == []
        engine.execute("SELECT 1")
        engine.execute("SELECT 3")
        engine.execute("SELECT 2")
        assert len(snow.connected) == 1  # one session, reused

    def test_the_session_it_asks_for(self) -> None:
        snow = FakeSnowflake()
        _engine(snow, statement_timeout_ms=7_000, connect_timeout_s=3).execute("SELECT 1")
        assert snow.connected == [
            {
                "account": "myorg-acct",
                "user": "WARDEN_READER",
                "password": "s3cret",
                "database": "WAREHOUSE",
                "schema": "PUBLIC",
                "warehouse": "XS",
                "role": "READER",
                "application": "sql-warden",
                "login_timeout": 3,
                "session_parameters": {
                    "STATEMENT_TIMEOUT_IN_SECONDS": 7,
                    "MULTI_STATEMENT_COUNT": 1,
                    "QUERY_TAG": "sql-warden",
                },
            }
        ]

    @pytest.mark.parametrize(("ms", "seconds"), [(1, 1), (999, 1), (5_000, 5), (5_001, 6)])
    def test_the_timeout_is_rounded_up_to_whole_seconds(self, ms: int, seconds: int) -> None:
        assert _engine(statement_timeout_ms=ms).statement_timeout_s == seconds

    def test_tables_without_a_schema_are_in_the_sessions(self) -> None:
        assert _engine().default_schema == "PUBLIC"
        other = SnowflakeEngine("snowflake://u@acct/db/reporting", connect=FakeSnowflake())
        assert other.default_schema == "REPORTING"

    @pytest.mark.parametrize(
        "settings", [{"statement_timeout_ms": 0}, {"max_rows": 0}, {"connect_timeout_s": -1}]
    )
    def test_settings_must_be_positive(self, settings: dict[str, Any]) -> None:
        with pytest.raises(ValueError, match="must be positive"):
            SnowflakeEngine(DSN, **settings)

    def test_a_connection_string_it_cant_read_is_an_error_at_once(self) -> None:
        with pytest.raises(ValueError, match="starts with snowflake://"):
            SnowflakeEngine("postgresql://u:pw@host/db")

    def test_snowflake_refusing_the_login(self) -> None:
        refused = errors.DatabaseError(
            msg="Incorrect username or password was specified.", errno=250001, sqlstate="08001"
        )
        with pytest.raises(EngineUnavailable) as excinfo:
            _engine(FakeSnowflake(refuse=refused)).execute("SELECT 1")
        assert str(excinfo.value) == (
            "could not connect to Snowflake: Incorrect username or password was specified."
        )

    def test_any_other_failure_to_connect_is_named_not_quoted(self) -> None:
        # Raised with the connection's settings in hand: its text could hold one of them.
        snow = FakeSnowflake(refuse=TypeError("unexpected keyword password='s3cret'"))
        with pytest.raises(EngineUnavailable) as excinfo:
            _engine(snow).tables()
        assert str(excinfo.value) == "could not connect to Snowflake: TypeError"

    def test_without_the_connector_it_says_how_to_get_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "snowflake.connector", None)
        with pytest.raises(EngineUnavailable, match=r"pip install 'sql-warden\[snowflake\]'"):
            SnowflakeEngine(DSN).execute("SELECT 1")

    def test_close_ends_the_session_and_the_next_use_opens_another(self) -> None:
        snow = FakeSnowflake()
        engine = _engine(snow)
        engine.execute("SELECT 1")
        engine.close()
        assert snow.connections[0].closed
        engine.execute("SELECT 1")
        assert len(snow.connections) == 2


class TestExecute:
    def test_rows_and_columns(self) -> None:
        snow = FakeSnowflake(default=Rows(("ID", "NAME"), [(1, "a"), (2, "b")]))
        result = _engine(snow).execute("SELECT ID, NAME FROM PUBLIC.PRODUCTS LIMIT 101")
        assert (result.columns, result.rows, result.truncated) == (
            ("ID", "NAME"),
            ((1, "a"), (2, "b")),
            False,
        )
        assert result.duration_ms >= 0
        assert snow.sql == ["SELECT ID, NAME FROM PUBLIC.PRODUCTS LIMIT 101"]

    def test_the_row_cap(self) -> None:
        snow = FakeSnowflake(default=Rows(("N",), [(n,) for n in range(10)]))
        result = _engine(snow, max_rows=3).execute("SELECT N FROM T")
        assert (result.rows, result.truncated) == (((0,), (1,), (2,)), True)
        cursor = snow.connections[0].cursors[-1]  # the first set the session up
        assert cursor.fetch_sizes == [4]  # one past the cap: enough to know there were more
        assert cursor.closed

    def test_exactly_the_cap_is_not_truncated(self) -> None:
        snow = FakeSnowflake(default=Rows(("N",), [(n,) for n in range(3)]))
        assert _engine(snow, max_rows=3).execute("SELECT N FROM T").truncated is False

    def test_snowflake_caps_the_rows_too_and_is_told_the_requests_tag(self) -> None:
        snow = FakeSnowflake()
        _engine(snow, max_rows=50).execute("SELECT 1", tag="sql-warden 1234")
        assert snow.statements == [
            (
                "SELECT 1",
                {"_statement_params": {"ROWS_PER_RESULTSET": 51, "QUERY_TAG": "sql-warden 1234"}},
            )
        ]

    def test_without_a_tag_the_sessions_stays(self) -> None:
        snow = FakeSnowflake()
        _engine(snow, max_rows=50).execute("SELECT 1")
        assert snow.statements[0][1] == {"_statement_params": {"ROWS_PER_RESULTSET": 51}}


class TestTables:
    def test_columns_are_grouped_by_table_in_order(self) -> None:
        snow = FakeSnowflake(
            default=Rows(
                ("TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME", "DATA_TYPE"),
                [
                    ("PUBLIC", "CUSTOMERS", "ID", "NUMBER"),
                    ("PUBLIC", "CUSTOMERS", "EMAIL", "TEXT"),
                    ("PUBLIC", "MixedCase", "Id", "NUMBER"),
                    ("REPORTING", "DAILY", "DAY", "DATE"),
                ],
            )
        )
        tables = _engine(snow, max_rows=1).tables()  # the row cap is for queries, not this
        assert [(t.schema, t.name, [(c.name, c.type) for c in t.columns]) for t in tables] == [
            ("PUBLIC", "CUSTOMERS", [("ID", "NUMBER"), ("EMAIL", "TEXT")]),
            ("PUBLIC", "MixedCase", [("Id", "NUMBER")]),
            ("REPORTING", "DAILY", [("DAY", "DATE")]),
        ]
        (statement, options) = snow.statements[0]
        assert "FROM information_schema.columns" in statement
        assert "table_schema <> 'INFORMATION_SCHEMA'" in statement
        assert options == {}


class TestSessionSetup:
    def test_a_new_session_drops_the_users_secondary_roles(self) -> None:
        # A user can have them on by default: they would lend the session other roles'
        # privileges, and the role check sees only the session's own.
        snow = FakeSnowflake()
        engine = _engine(snow)
        engine.execute("SELECT 1")
        engine.execute("SELECT 2")
        assert snow.connections[0].setup == [SESSION_SETUP]  # once a session, before the rest
        assert snow.sql == ["SELECT 1", "SELECT 2"]

    def test_so_does_the_session_that_replaces_a_lost_one(self) -> None:
        snow = FakeSnowflake(answers=[LOST])
        _engine(snow).execute("SELECT 1")
        assert [connection.setup for connection in snow.connections] == [[SESSION_SETUP]] * 2

    def test_a_session_that_cant_be_set_up_is_not_used(self) -> None:
        refused = errors.ProgrammingError(
            msg="SQL compilation error: role is restricted.", errno=1003, sqlstate="42000"
        )
        snow = FakeSnowflake(refuse_setup=refused)
        with pytest.raises(EngineUnavailable) as excinfo:
            _engine(snow).execute("SELECT 1")
        assert str(excinfo.value) == (
            "could not set up the Snowflake session: SQL compilation error: role is restricted."
        )
        assert snow.sql == []
        assert all(connection.closed for connection in snow.connections)


def _role(
    enabled: list[str], grants: list[tuple[str, str, str | None, str, str]], role: str = "READER"
) -> FakeSnowflake:
    """A stand-in that answers role()'s three statements."""
    return FakeSnowflake(
        answers=[
            Rows(("CURRENT_ROLE()",), [(role,)]),
            Rows(("ROLE_NAME",), [(name,) for name in enabled]),
            Rows(
                ("GRANTEE", "OBJECT_TYPE", "OBJECT_SCHEMA", "OBJECT_NAME", "PRIVILEGE_TYPE"), grants
            ),
        ]
    )


class TestRole:
    def test_a_role_that_holds_nothing_that_writes(self) -> None:
        snow = _role(["PUBLIC", "READER"], [])
        assert _engine(snow).role() == RoleReport("READER")
        current, enabled, writes = snow.sql
        assert current == "SELECT CURRENT_ROLE()"
        assert "information_schema.enabled_roles" in enabled
        # Only what the session's roles hold, and only what changes the database.
        assert "FROM information_schema.object_privileges" in writes
        assert "grantee IN (SELECT role_name FROM information_schema.enabled_roles)" in writes
        for privilege in ("'INSERT'", "'UPDATE'", "'DELETE'", "'TRUNCATE'", "'OWNERSHIP'"):
            assert privilege in writes
        assert "privilege_type LIKE 'CREATE%'" in writes
        assert all(options == {} for _, options in snow.statements)

    def test_privileges_that_write(self) -> None:
        snow = _role(
            ["PUBLIC", "READER"],
            [
                ("READER", "SCHEMA", None, "PUBLIC", "CREATE TABLE"),
                ("READER", "SCHEMA", None, "PUBLIC", "CREATE VIEW"),
                ("READER", "TABLE", "PUBLIC", "ORDERS", "INSERT"),
                ("READER", "TABLE", "PUBLIC", "ORDERS", "UPDATE"),
                ("READER", "TABLE", "PUBLIC", "SCRATCH", "OWNERSHIP"),
            ],
        )
        report = _engine(snow).role()
        assert not report.read_only
        assert report.writes == (
            "has CREATE TABLE, CREATE VIEW on schema PUBLIC",
            "has INSERT, UPDATE on table PUBLIC.ORDERS",
            "has OWNERSHIP on table PUBLIC.SCRATCH",
        )

    def test_what_it_holds_through_another_role_says_which(self) -> None:
        snow = _role(
            ["ETL", "PUBLIC", "READER"],
            [
                ("ETL", "TABLE", "PUBLIC", "ORDERS", "DELETE"),
                ("PUBLIC", "TABLE", "PUBLIC", "ORDERS", "INSERT"),
                ("READER", "TABLE", "PUBLIC", "ORDERS", "INSERT"),
            ],
        )
        assert _engine(snow).role().writes == (
            "has DELETE on table PUBLIC.ORDERS, through role ETL",
            "has INSERT on table PUBLIC.ORDERS, through role PUBLIC",
            "has INSERT on table PUBLIC.ORDERS",
        )

    @pytest.mark.parametrize("admin", ["ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN"])
    def test_a_role_that_administers_the_account(self, admin: str) -> None:
        snow = _role(["PUBLIC", admin], [], role=admin)
        assert _engine(snow).role() == RoleReport(
            admin, (f"holds {admin}, which administers the account",)
        )

    def test_a_session_with_no_role_is_an_error(self) -> None:
        snow = _role([], [], role="")
        with pytest.raises(EngineError, match="did not say which role"):
            _engine(snow).role()

    def test_a_failure_is_snowflakes_own(self) -> None:
        with pytest.raises(QueryFailed, match="does not exist or not authorized"):
            _engine(FakeSnowflake(answers=[COMPILE_ERROR])).role()

    def test_a_lost_session_is_replaced_and_asked_again(self) -> None:
        snow = _role(["READER"], [])
        snow.answers.insert(0, LOST)
        assert _engine(snow).role() == RoleReport("READER")
        assert len(snow.connections) == 2


class TestExplain:
    def _explained(self, plan: object, **options: Any) -> tuple[Any, FakeSnowflake]:
        snow = FakeSnowflake(default=Rows(("content",), [(plan,)]))
        return _engine(snow).explain("SELECT SUM(QUANTITY) FROM PUBLIC.ORDERS", **options), snow

    def test_it_plans_and_never_runs(self) -> None:
        _, snow = self._explained(json.dumps(_plan("full_scan")), tag="sql-warden abcd")
        assert snow.statements == [
            (
                "EXPLAIN USING JSON SELECT SUM(QUANTITY) FROM PUBLIC.ORDERS",
                {"_statement_params": {"QUERY_TAG": "sql-warden abcd"}},
            )
        ]

    def test_the_cost_is_the_bytes_it_may_scan(self) -> None:
        estimate, _ = self._explained(json.dumps(_plan("full_scan")))
        assert (estimate.total_cost, estimate.unit, estimate.est_rows) == (
            6871947264,
            "bytes",
            None,
        )
        assert estimate.top_node == "TableScan on WAREHOUSE.PUBLIC.ORDERS (412 of 412 partitions)"
        assert estimate.raw == _plan("full_scan")

    def test_a_plan_already_decoded(self) -> None:
        estimate, _ = self._explained(_plan("pruned_scan"))
        assert estimate.total_cost == 50331648

    @pytest.mark.parametrize("plan", ["not json", "[1, 2]", "{}", '{"GlobalStats": {}}', 42, None])
    def test_a_plan_it_cant_read_is_no_estimate(self, plan: object) -> None:
        # An EngineError, so the cost check refuses with COST_UNAVAILABLE: fail closed.
        with pytest.raises(EngineError, match="a plan sql-warden can't read"):
            self._explained(plan)

    def test_no_plan_at_all(self) -> None:
        snow = FakeSnowflake(default=Rows(("content",), []))
        with pytest.raises(EngineError, match="EXPLAIN returned no plan"):
            _engine(snow).explain("SELECT 1")

    def test_a_query_snowflake_rejects_while_compiling(self) -> None:
        with pytest.raises(QueryFailed, match="Object 'NOSUCH' does not exist") as excinfo:
            _engine(FakeSnowflake(answers=[COMPILE_ERROR])).explain("SELECT * FROM NOSUCH")
        assert excinfo.value.sqlstate == "42S02"


class TestPlans:
    @pytest.mark.parametrize(
        ("name", "bytes_", "top"),
        [
            ("docs_join", 1024, "TableScan on TESTDB.TEMPORARY_DOC_TEST.Z2 (1 of 1 partitions)"),
            (
                "full_scan",
                6871947264,
                "TableScan on WAREHOUSE.PUBLIC.ORDERS (412 of 412 partitions)",
            ),
            ("pruned_scan", 50331648, "TableScan on WAREHOUSE.PUBLIC.ORDERS (3 of 412 partitions)"),
            (
                "join_two_tables",
                6888724480,
                "TableScan on WAREHOUSE.PUBLIC.ORDERS (412 of 412 partitions)",
            ),
            ("no_table", 0, "Result"),
        ],
    )
    def test_each_saved_plan(self, name: str, bytes_: int, top: str) -> None:
        estimate = cost_estimate(_plan(name))
        assert (estimate.total_cost, estimate.top_node) == (bytes_, top)
        assert (estimate.unit, estimate.est_rows) == ("bytes", None)

    def test_an_operation_in_a_few_words(self) -> None:
        assert describe_operation({"operation": "InnerJoin", "expressions": ["x"]}) == "InnerJoin"
        assert describe_operation({"id": 3}) == "?"

    @pytest.mark.parametrize(
        ("count", "text"),
        [
            (0, "0 B"),
            (512, "512 B"),
            (1024, "1 KiB"),
            (1536, "1.5 KiB"),
            (50331648, "48 MiB"),
            (6871947264, "6.4 GiB"),
            (10 * 1024**3, "10 GiB"),
            (5 * 1024**5, "5,120 TiB"),
        ],
    )
    def test_bytes_as_people_read_them(self, count: int, text: str) -> None:
        assert format_bytes(count) == text


class TestErrors:
    def test_a_statement_snowflake_cancelled(self) -> None:
        with pytest.raises(QueryTimeout) as excinfo:
            _engine(FakeSnowflake(answers=[TIMED_OUT])).execute("SELECT 1")
        assert str(excinfo.value) == (
            "query cancelled (the statement timeout is 5 s): Statement reached its statement "
            "or warehouse timeout of 5 second(s) and was canceled."
        )

    def test_a_query_snowflake_rejects(self) -> None:
        snow = FakeSnowflake(answers=[COMPILE_ERROR])
        with pytest.raises(QueryFailed) as excinfo:
            _engine(snow).execute("SELECT * FROM NOSUCH")
        assert str(excinfo.value) == (
            "SQL compilation error:\nObject 'NOSUCH' does not exist or not authorized."
        )
        assert excinfo.value.sqlstate == "42S02"
        assert len(snow.connections) == 1  # its fault, not the session's: no reconnect

    @pytest.mark.parametrize("lost", [LOST, EXPIRED], ids=["connection", "session"])
    def test_a_lost_session_is_replaced_once(self, lost: BaseException) -> None:
        snow = FakeSnowflake(answers=[lost])
        result = _engine(snow).execute("SELECT ID FROM T")
        assert result.rows == ((1,), (2,), (3,))
        assert [connection.closed for connection in snow.connections] == [True, False]
        assert snow.sql == ["SELECT ID FROM T", "SELECT ID FROM T"]

    def test_and_only_once(self) -> None:
        snow = FakeSnowflake(answers=[LOST, LOST])
        with pytest.raises(EngineUnavailable, match="could not reach Snowflake: Connection reset"):
            _engine(snow).execute("SELECT 1")
        assert len(snow.connections) == 2

    def test_a_bug_is_not_dressed_up_as_snowflakes(self) -> None:
        snow = FakeSnowflake(answers=[RuntimeError("bug")])
        with pytest.raises(RuntimeError, match="bug"):
            _engine(snow).execute("SELECT 1")


CATALOG = Rows(
    ("TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME", "DATA_TYPE"),
    [
        ("PUBLIC", "CUSTOMERS", "ID", "NUMBER"),
        ("PUBLIC", "CUSTOMERS", "EMAIL", "TEXT"),
        ("PUBLIC", "CUSTOMERS", "SSN", "TEXT"),
        ("PUBLIC", "ORDERS", "ID", "NUMBER"),
        ("PUBLIC", "ORDERS", "QUANTITY", "NUMBER"),
    ],
)


def _plan_rows(name: str) -> Rows:
    return Rows(("content",), [(json.dumps(_plan(name)),)])


def _refusal(decision: Decision) -> tuple[str, str, str]:
    refused = decision.refused_by
    assert refused is not None
    assert refused.refusal is not None
    return refused.check, refused.refusal.code, refused.refusal.reason


class TestThroughTheWarden:
    def _warden(self, snow: FakeSnowflake, **settings: Any) -> Warden:
        engine = _engine(snow, max_rows=100)
        return Warden(
            engine,
            audit=MemoryAuditSink(),
            dialect="snowflake",
            default_schema=engine.default_schema,
            profile="support",
            access=Access({("PUBLIC", "CUSTOMERS"): "*", ("PUBLIC", "ORDERS"): "*"}),
            **settings,
        )

    def test_a_query_is_checked_planned_run_and_masked(self) -> None:
        rows = Rows(("ID", "SSN"), [(1, "123-45-6789"), (2, "987-65-4321")])
        snow = FakeSnowflake(answers=[CATALOG, _plan_rows("pruned_scan"), rows])
        masks = {("PUBLIC", "CUSTOMERS", "SSN"): MaskRule.model_validate("partial")}
        warden = self._warden(snow, masks=masks)
        outcome = warden.run("select id, ssn from customers")
        assert outcome.result is not None
        assert outcome.result.rows == ((1, "*******6789"), (2, "*******4321"))
        ran = "SELECT ID, SSN FROM PUBLIC.CUSTOMERS LIMIT 101"
        assert snow.sql[1:] == [f"EXPLAIN USING JSON {ran}", ran]
        assert outcome.decision.cost is not None
        assert outcome.decision.cost.unit == "bytes"

    def test_snowflake_is_told_the_audit_id_of_what_it_plans_and_runs(self) -> None:
        snow = FakeSnowflake(answers=[CATALOG, _plan_rows("no_table")])
        warden = self._warden(snow)
        outcome = warden.run("select 1")
        tag = f"sql-warden {outcome.decision.audit_id}"
        tagged = [options["_statement_params"] for _, options in snow.statements[1:]]
        assert [parameters.get("QUERY_TAG") for parameters in tagged] == [tag, tag]
        assert snow.statements[0][1] == {}  # the catalog isn't any one request's
        assert isinstance(warden.audit, MemoryAuditSink)
        assert warden.audit.events[0].id == outcome.decision.audit_id

    def test_a_scan_over_the_limit_is_refused_in_bytes(self) -> None:
        snow = FakeSnowflake(answers=[CATALOG, _plan_rows("full_scan")])
        warden = self._warden(snow, cost=CostConfig(max_total_cost=1024**3))
        check, code, reason = _refusal(warden.run("select sum(quantity) from orders").decision)
        assert (check, code) == ("cost", "COST_TOO_HIGH")
        assert reason == (
            "this query may scan 6.4 GiB, over profile support's limit of 1 GiB; most of it "
            "is TableScan on WAREHOUSE.PUBLIC.ORDERS (412 of 412 partitions). Filter on what "
            "the table is clustered by (often a date) so fewer partitions are read, and select "
            "only the columns needed"
        )
        assert len(snow.sql) == 2  # the catalog and the plan: nothing ran

    def test_a_pruned_scan_fits(self) -> None:
        snow = FakeSnowflake(answers=[CATALOG, _plan_rows("pruned_scan")])
        warden = self._warden(snow, cost=CostConfig(max_total_cost=1024**3))
        assert warden.check("select id from orders where id > 5").allowed

    def test_a_session_budget_adds_up_the_bytes(self) -> None:
        plans = [_plan_rows("pruned_scan"), Rows(), _plan_rows("pruned_scan"), Rows()]
        snow = FakeSnowflake(answers=[CATALOG, *plans, _plan_rows("pruned_scan")])
        budget = BudgetConfig(max_total_cost=120 * 1024**2)  # 48 MiB a query: two fit
        warden = self._warden(snow, budget=budget)
        sql = "select id from orders where id > 5"
        assert warden.run(sql).decision.allowed
        assert warden.run(sql).decision.allowed
        assert _refusal(warden.run(sql).decision)[1] == "COST_OVER_BUDGET"

    def test_a_plan_that_cant_be_read_refuses_the_query(self) -> None:
        snow = FakeSnowflake(answers=[CATALOG, Rows(("content",), [("{}",)])])
        check, code, reason = _refusal(self._warden(snow).run("select id from orders").decision)
        assert (check, code) == ("cost", "COST_UNAVAILABLE")
        assert "a plan sql-warden can't read" in reason

    def test_a_compile_error_is_a_refusal_before_anything_runs(self) -> None:
        snow = FakeSnowflake(answers=[CATALOG, COMPILE_ERROR])
        check, code, _ = _refusal(self._warden(snow).run("select id from orders").decision)
        assert (check, code) == ("cost", "PLAN_FAILED")

    def test_a_timeout_while_running_is_reported(self) -> None:
        snow = FakeSnowflake(answers=[CATALOG, _plan_rows("pruned_scan"), TIMED_OUT])
        outcome = self._warden(snow).run("select id from orders")
        assert isinstance(outcome.error, QueryTimeout)


POLICY = f"""\
version: 1
warehouse:
  engine: snowflake
  dsn: {DSN}
  max_rows: 50
default_profile: public
profiles:
  public:
    dsn: snowflake://WARDEN_PUBLIC:pub1ic@myorg-acct/warehouse/public?role=PUBLIC_READER
    tables:
      PUBLIC.ORDERS: [ID, QUANTITY]
    cost:
      max_total_cost: 1073741824
  admin:
    tables: "*"
"""


class TestConfig:
    def test_snowflake_with_its_connection_string(self) -> None:
        config = parse_config(POLICY)
        assert (config.warehouse.engine, config.warehouse.dialect) == ("snowflake", "snowflake")
        assert config.warehouse.dsn == DSN

    def test_the_cost_limit_defaults_to_ten_gib_of_scanning(self) -> None:
        assert parse_config(POLICY).cost.max_total_cost == SNOWFLAKE_MAX_TOTAL_COST == 10 * 1024**3
        explicit = parse_config(POLICY + "cost:\n  max_total_cost: 5000\n")
        assert explicit.cost.max_total_cost == 5000
        assert parse_config("version: 1").cost.max_total_cost == 1_000_000  # Postgres's units

    @pytest.mark.parametrize(
        ("text", "problem"),
        [
            (
                "warehouse:\n  engine: snowflake\n",
                "warehouse: the snowflake engine needs a dsn: snowflake://USER:PASSWORD@",
            ),
            (
                "warehouse:\n  engine: snowflake\n  dsn: postgresql://u:hunter2@h/db\n",
                "warehouse: a Snowflake connection string starts with snowflake://",
            ),
            (
                "warehouse:\n  engine: snowflake\n  dsn: snowflake://u:hunter2@acct\n",
                "warehouse: the connection string needs the database",
            ),
            (
                "warehouse:\n  dsn: snowflake://u:hunter2@acct/db\n",
                "warehouse: is a Snowflake connection string, but warehouse.engine is postgres",
            ),
            (
                "warehouse:\n  engine: snowflake\n  dsn: snowflake://u:hunter2@acct/db\n"
                "profiles:\n  p:\n    dsn: postgresql://p:hunter2@h/db\n",
                "profile p's dsn a Snowflake connection string starts with snowflake://",
            ),
            (
                "profiles:\n  p:\n    dsn: snowflake://p:hunter2@acct/db\n",
                "profile p's dsn is a Snowflake connection string, but warehouse.engine is",
            ),
            ("warehouse:\n  engine: mysql\n", "warehouse.engine: Input should be 'postgres' or"),
        ],
    )
    def test_a_connection_that_doesnt_fit_the_engine(self, text: str, problem: str) -> None:
        with pytest.raises(ConfigError) as excinfo:
            parse_config("version: 1\n" + text)
        assert problem in str(excinfo.value)
        assert "hunter2" not in str(excinfo.value)


@pytest.fixture
def snow(monkeypatch: pytest.MonkeyPatch) -> FakeSnowflake:
    """The CLI's SnowflakeEngine, connecting to a stand-in."""
    fake = FakeSnowflake()

    def factory(dsn: str, **settings: Any) -> SnowflakeEngine:
        return SnowflakeEngine(dsn, connect=fake, **settings)

    monkeypatch.setattr(cli_module, "SnowflakeEngine", factory)
    return fake


class TestCli:
    def test_validate_describes_it_without_passwords(self, isolated_cli: Path) -> None:
        (isolated_cli / "warden.yaml").write_text(POLICY)
        outcome = CliRunner().invoke(cli, ["config", "validate"])
        assert outcome.exit_code == 0, outcome.output
        lines = outcome.output.splitlines()
        assert lines[1] == (
            "  warehouse: snowflake at myorg-acct/WAREHOUSE/PUBLIC as WARDEN_READER "
            "(role READER, warehouse XS)"
        )
        assert "  cost:      refused above an estimated 10 GiB scanned" in lines
        assert (
            "  profiles:  public (default): connects to myorg-acct/WAREHOUSE/PUBLIC as "
            "WARDEN_PUBLIC (role PUBLIC_READER)"
        ) in lines
        assert "               refused above an estimated 1 GiB scanned" in lines
        assert "s3cret" not in outcome.output
        assert "pub1ic" not in outcome.output
        assert "!" not in outcome.output  # every name is as Snowflake stores it

    def test_validate_points_out_names_snowflake_stores_otherwise(self, isolated_cli: Path) -> None:
        lowered = POLICY.replace("PUBLIC.ORDERS: [ID, QUANTITY]", "public.orders: [ID, quantity]")
        (isolated_cli / "warden.yaml").write_text(lowered)
        lines = CliRunner().invoke(cli, ["config", "validate"]).output.splitlines()
        assert (
            "               ! public.orders is not upper case: Snowflake stores a name as "
            "PUBLIC.ORDERS unless it was created in quotes"
        ) in lines
        assert any(line.startswith("               ! quantity is not upper case") for line in lines)

    def test_a_query_runs_as_the_profiles_role(
        self, isolated_cli: Path, snow: FakeSnowflake, audit_sinks: AuditSinks
    ) -> None:
        (isolated_cli / "warden.yaml").write_text(POLICY)
        orders = Rows(
            ("TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME", "DATA_TYPE"),
            [("PUBLIC", "ORDERS", name, "NUMBER") for name in ("ID", "QUANTITY", "PRICE")],
        )
        snow.answers = [orders, _plan_rows("pruned_scan"), Rows(("ID",), [(7,)])]
        outcome = CliRunner().invoke(cli, ["query", "select id from orders"])
        assert outcome.exit_code == 0, outcome.output
        assert outcome.output.splitlines()[:3] == ["ID", "--", "7"]
        assert "note: added LIMIT 51 (row cap 50 + 1 to detect truncation)" in outcome.output
        assert snow.connected[0]["user"] == "WARDEN_PUBLIC"
        assert snow.sql[-1] == "SELECT ID FROM PUBLIC.ORDERS LIMIT 51"
        (event,) = audit_sinks.events
        assert (event.profile, event.cost_estimate, event.rows_returned) == ("public", 50331648, 1)

    def test_a_refusal_reads_the_same(
        self, isolated_cli: Path, snow: FakeSnowflake, audit_sinks: AuditSinks
    ) -> None:
        (isolated_cli / "warden.yaml").write_text(POLICY)
        orders = Rows(
            ("TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME", "DATA_TYPE"),
            [("PUBLIC", "ORDERS", name, "NUMBER") for name in ("ID", "QUANTITY", "PRICE")],
        )
        snow.answers = [orders]
        outcome = CliRunner().invoke(cli, ["check", "select price from orders"])
        assert outcome.exit_code == EXIT_REFUSED
        assert "COLUMN_NOT_ALLOWED: column PRICE is not available to profile public" in (
            outcome.output
        )

    def test_a_dsn_on_the_command_line_that_isnt_snowflakes(
        self, isolated_cli: Path, audit_sinks: AuditSinks
    ) -> None:
        (isolated_cli / "warden.yaml").write_text(POLICY)
        outcome = CliRunner().invoke(
            cli, ["query", "select 1", "--profile", "admin", "--dsn", "postgresql://u:pw@h/db"]
        )
        assert outcome.exit_code == 1
        assert "warehouse dsn: a Snowflake connection string starts with snowflake://" in (
            outcome.output
        )
        assert "pw@" not in outcome.output
