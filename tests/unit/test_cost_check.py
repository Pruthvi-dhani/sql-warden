"""The cost check: the planner's estimate against the profile's limit, before anything runs."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import EXIT_REFUSED, cli
from sql_warden.config import ConfigError, CostConfig, parse_config
from sql_warden.engines import CostEstimate, EngineUnavailable, QueryFailed, QueryTimeout
from sql_warden.models import Decision, RefusalCode
from sql_warden.pipeline.cost import format_cost
from sql_warden.profiles import select_profile
from sql_warden.render import format_decision
from sql_warden.server import describe
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine
from tests.unit.test_access_check import CATALOG, PUBLIC

CROSS_JOIN = CostEstimate(total_cost=12847522945.56, est_rows=1, top_node="Nested Loop")


def _warden(
    engine: FakeEngine, limit: float = 1000, *, sink: MemoryAuditSink | None = None
) -> Warden:
    return Warden(
        engine,
        audit=sink or MemoryAuditSink(),
        profile="public",
        cost=CostConfig(max_total_cost=limit),
    )


def _estimate(total: float) -> FakeEngine:
    return FakeEngine(
        estimate=CostEstimate(total_cost=total, est_rows=3, top_node="Seq Scan on orders")
    )


class TestTheLimit:
    @pytest.mark.parametrize("total", [0.0, 999.99, 1000.0])
    def test_up_to_the_limit_is_allowed(self, total: float) -> None:
        assert _warden(_estimate(total)).check("select id from orders").allowed

    def test_over_it_is_refused_with_the_estimate_the_limit_and_the_costliest_step(self) -> None:
        engine = _estimate(1000.01)
        outcome = _warden(engine).run("select id from orders")
        refused = outcome.decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert (refused.check, refused.refusal.code) == ("cost", RefusalCode.COST_TOO_HIGH)
        assert refused.refusal.reason == (
            "the planner estimates this query at 1,000, over profile public's limit of 1,000; "
            "most of it is Seq Scan on orders. Filter on indexed columns, join on keys rather "
            "than crossing tables, or aggregate over fewer rows"
        )
        assert engine.executed == []  # planned, never run

    def test_big_numbers_read_as_numbers(self) -> None:
        refused = _warden(FakeEngine(estimate=CROSS_JOIN), 1_000_000).check("select 1").refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert "at 12,847,522,946, over profile public's limit of 1,000,000; most of it is " in (
            refused.refusal.reason
        )

    def test_the_default_limit(self) -> None:
        assert CostConfig().max_total_cost == 1_000_000
        warden = Warden(FakeEngine(estimate=CROSS_JOIN), audit=MemoryAuditSink())
        assert warden.check("select 1").refused_by is not None


class TestWhatIsExplained:
    def test_exactly_the_sql_that_would_run(self) -> None:
        engine = FakeEngine()
        decision = _warden(engine).check("select id from products -- note\nwhere id < 10")
        assert decision.sql == "SELECT id FROM products WHERE id < 10 LIMIT 101"
        assert engine.explained == [decision.sql]

    def test_and_then_runs_that_same_sql(self) -> None:
        engine = FakeEngine()
        _warden(engine).run("select id from products")
        assert engine.explained == engine.executed == ["SELECT id FROM products LIMIT 101"]

    @pytest.mark.parametrize(
        "sql", ["select (1", "delete from products", "select 1; select 2", "select pg_sleep(1)"]
    )
    def test_nothing_the_shape_check_refuses(self, sql: str) -> None:
        engine = FakeEngine()
        assert not _warden(engine).check(sql).allowed
        assert engine.explained == []

    def test_nothing_the_access_check_refuses(self) -> None:
        engine = FakeEngine(catalog=CATALOG)
        warden = Warden(engine, audit=MemoryAuditSink(), profile="public", access=PUBLIC)
        refused = warden.check("select salary_cents from employee_salaries").refused_by
        assert refused is not None
        assert refused.check == "access"
        assert engine.explained == []  # unvetted SQL never reaches even the planner
        assert warden.check("select name from products").allowed
        assert engine.explained == ["SELECT name FROM public.products LIMIT 101"]


class TestUnknownCost:
    @pytest.mark.parametrize(
        ("error", "code", "reason"),
        [
            (
                QueryFailed("division by zero"),
                RefusalCode.PLAN_FAILED,
                "the database rejected the query while planning it: division by zero",
            ),
            (
                EngineUnavailable("could not connect to the database: refused"),
                RefusalCode.COST_UNAVAILABLE,
                "could not estimate the query's cost: could not connect to the database: refused",
            ),
            (
                QueryTimeout("query cancelled after the 5000 ms statement timeout"),
                RefusalCode.COST_UNAVAILABLE,
                "could not estimate the query's cost: query cancelled after the 5000 ms "
                "statement timeout",
            ),
        ],
    )
    def test_is_refused_and_nothing_runs(
        self, error: Exception, code: RefusalCode, reason: str
    ) -> None:
        engine = FakeEngine(explain_error=error)  # type: ignore[arg-type]
        outcome = _warden(engine).run("select 1 / 0")
        refused = outcome.decision.refused_by
        assert refused is not None
        assert refused.refusal is not None
        assert (refused.check, refused.refusal.code) == ("cost", code)
        assert refused.refusal.reason == reason
        assert outcome.decision.cost is None
        assert engine.executed == []


class TestWhereTheEstimateGoes:
    def test_the_decision_carries_it_and_the_limit(self) -> None:
        for total, allowed in ((10.0, True), (5000.0, False)):
            decision = _warden(_estimate(total)).check("select 1")
            assert decision.allowed is allowed
            assert decision.cost is not None
            assert (decision.cost.total_cost, decision.cost_limit) == (total, 1000)

    def test_the_audit_record_has_it_allowed_or_refused(self) -> None:
        sink = MemoryAuditSink()
        _warden(_estimate(12.5), sink=sink).run("select 1")
        _warden(_estimate(5000.0), sink=sink).run("select 2")
        assert [(e.decision, e.cost_estimate) for e in sink.events] == [
            ("allowed", 12.5),
            ("refused", 5000.0),
        ]
        assert sink.events[1].code == "COST_TOO_HIGH"

    def test_a_refusal_before_the_cost_check_has_no_estimate(self) -> None:
        sink = MemoryAuditSink()
        decision = _warden(FakeEngine(), sink=sink).check("delete from orders")
        assert (decision.cost, decision.cost_limit) == (None, None)
        assert sink.events[0].cost_estimate is None

    def test_the_response_has_it(self) -> None:
        response = describe(_warden(_estimate(5000.0)).check("select 1"))
        assert response.cost is not None
        assert response.cost.model_dump(exclude_none=True) == {  # as the tools return it
            "total_cost": 5000.0,
            "max_total_cost": 1000.0,
            "est_rows": 3,
            "top_node": "Seq Scan on orders",
        }
        assert describe(_warden(FakeEngine()).check("delete from x")).cost is None

    def test_the_cli_shows_it_for_an_allowed_query(self) -> None:
        def lines(decision: Decision) -> list[str]:
            return format_decision(decision, dry_run=True).splitlines()

        allowed = lines(_warden(_estimate(14542.56), 1_000_000).check("select 1"))
        assert "  cost: 14,543 of 1,000,000 allowed (most of it: Seq Scan on orders)" in allowed
        refused = lines(_warden(_estimate(5000.0)).check("select 1"))
        assert not any(line.startswith("  cost:") for line in refused)  # the reason says it


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (0, "0"),
        (500, "500"),
        (8.44, "8.44"),
        (999.994, "999.99"),
        (1000, "1,000"),
        (14542.56, "14,543"),
        (1e10, "10,000,000,000"),
    ],
)
def test_format_cost(value: float, text: str) -> None:
    assert format_cost(value) == text


POLICY = """\
version: 1
default_profile: public
warehouse:
  max_rows: 100
cost:
  max_total_cost: 50000
profiles:
  public:
    tables:
      public.products: [id, name]
    max_rows: 20
    cost:
      max_total_cost: 500
  admin:
    tables: "*"
"""


class TestConfig:
    def test_a_profile_overrides_the_limits_it_sets(self) -> None:
        config = parse_config(POLICY)
        public, admin = select_profile(config, "public"), select_profile(config, "admin")
        assert (public.max_rows, public.cost.max_total_cost) == (20, 500)
        assert (admin.max_rows, admin.cost.max_total_cost) == (None, 50000)

    def test_an_empty_override_keeps_the_top_level_limits(self) -> None:
        config = parse_config(
            POLICY.replace("      max_total_cost: 500\n", "").replace(
                "    cost:\n", "    cost: {}\n"
            )
        )
        assert config.profiles is not None
        assert config.profiles["public"].cost == CostConfig()  # set, but setting nothing
        assert select_profile(config, "public").cost.max_total_cost == 50000

    def test_without_profiles(self) -> None:
        config = parse_config("version: 1\ncost:\n  max_total_cost: 42\n")
        profile = select_profile(config)
        assert (profile.max_rows, profile.cost.max_total_cost) == (None, 42)

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("cost:\n  max_total_cost: 0\n", "cost.max_total_cost: Input should be greater than 0"),
            (
                "cost:\n  max_total_cost: -5\n",
                "cost.max_total_cost: Input should be greater than 0",
            ),
            ("cost:\n  max_rows: 5\n", "cost.max_rows: Extra inputs are not permitted"),
            (
                "profiles:\n  p:\n    max_rows: 0\n",
                "profiles.p.max_rows: Input should be greater than 0",
            ),
            (
                "profiles:\n  p:\n    cost:\n      max_estimated_rows: 5\n",
                "profiles.p.cost.max_estimated_rows: Extra inputs are not permitted",
            ),
        ],
    )
    def test_problems(self, text: str, message: str) -> None:
        with pytest.raises(ConfigError) as caught:
            parse_config("version: 1\n" + text)
        assert message in str(caught.value)


class TestCli:
    def test_validate_shows_the_limits_and_caps(self, policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["config", "validate"])
        assert outcome.exit_code == 0, outcome.output
        lines = outcome.output.splitlines()
        assert "  cost:      refused above an estimated 50,000" in lines
        assert lines[-5:] == [
            "               reads public.products (id, name)",
            "               max 20 rows",
            "               refused above an estimated 500",
            "             admin: connects with warehouse.dsn",
            "               reads every table its role can",
        ]

    @pytest.fixture
    def policy(self, isolated_cli: Path) -> Path:
        path = isolated_cli / "warden.yaml"
        path.write_text(POLICY)
        return path

    def test_each_profile_gets_its_own_row_cap(
        self, engines: list[FakeEngine], policy: Path
    ) -> None:
        public = CliRunner().invoke(cli, ["check", "select id from products"])
        admin = CliRunner().invoke(cli, ["check", "select id from products", "--profile", "admin"])
        assert "  would run: SELECT id FROM public.products LIMIT 21" in public.output.splitlines()
        assert "  would run: SELECT id FROM public.products LIMIT 101" in admin.output.splitlines()
        assert [engine.max_rows for engine in engines] == [20, 100]

    def test_max_rows_doesnt_change_a_profiles_own_cap(
        self, engines: list[FakeEngine], policy: Path
    ) -> None:
        CliRunner().invoke(cli, ["check", "select id from products", "--max-rows", "5000"])
        CliRunner().invoke(cli, ["check", "select 1", "--max-rows", "5000", "--profile", "admin"])
        assert [engine.max_rows for engine in engines] == [20, 5000]

    def test_each_profile_gets_its_own_limit(
        self, engines: list[FakeEngine], policy: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        estimate = CostEstimate(1000.0, 1, "Seq Scan on products")
        monkeypatch.setattr(FakeEngine, "explain", lambda self, sql, tag=None: estimate)
        public = CliRunner().invoke(cli, ["check", "select id from products"])
        admin = CliRunner().invoke(cli, ["check", "select id from products", "--profile", "admin"])
        assert public.exit_code == EXIT_REFUSED
        assert "COST_TOO_HIGH" in public.output
        assert "over profile public's limit of 500" in public.output
        assert admin.exit_code == 0, admin.output
        assert "  cost: 1,000 of 50,000 allowed (most of it: Seq Scan on products)" in admin.output
