import re
from pathlib import Path

from click.testing import CliRunner

from sql_warden.cli import EXIT_REFUSED, cli
from tests.unit.conftest import FakeEngine


def test_allowed_query_shows_each_check_and_executes_nothing(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["check", "select id from products"])
    assert outcome.exit_code == 0, outcome.output
    parse, shape, cost, *rest = outcome.output.splitlines()
    assert re.fullmatch(r"✓ parse  \d+\.\d ms", parse)
    assert re.fullmatch(r"✓ shape  \d+\.\d ms", shape)
    assert re.fullmatch(r"✓ cost   \d+\.\d ms", cost)
    assert rest == [
        "→ allowed (profile all; dry run, nothing was executed)",
        "  cost: 1 of 1,000,000 allowed (most of it: Result)",
        "  note: added LIMIT 101 (row cap 100 + 1 to detect truncation)",
        "  would run: SELECT id FROM products LIMIT 101",
    ]
    assert engines[0].executed == []
    assert engines[0].explained == ["SELECT id FROM products LIMIT 101"]  # planned, not run


def test_the_row_cap_option_changes_the_limit(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["check", "select id from products", "--max-rows", "5"])
    assert "  would run: SELECT id FROM products LIMIT 6" in outcome.output.splitlines()


def test_shape_policy_comes_from_the_config(engines: list[FakeEngine], isolated_cli: Path) -> None:
    (isolated_cli / "warden.yaml").write_text("version: 1\nshape:\n  limit: require\n")
    outcome = CliRunner().invoke(cli, ["check", "select id from products"])
    assert outcome.exit_code == 2
    assert "✗ shape  LIMIT_REQUIRED: " in outcome.output


def test_refused_query_names_the_check_code_and_reason(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["check", "select * from orders where"])
    assert outcome.exit_code == 2
    assert outcome.output.splitlines()[0].startswith("✗ parse  PARSE_ERROR: ")
    assert outcome.output.splitlines()[-1] == "→ refused by parse (profile all)"
    assert engines[0].executed == []


def test_empty_query_is_refused(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["check", "  ;  "])
    assert outcome.exit_code == 2
    assert "PARSE_ERROR: the query is empty" in outcome.output


def test_check_needs_the_database_only_for_the_cost() -> None:
    # The real engine, pointed at a port nothing listens on. The checks before the cost check
    # still decide without it; the cost check can't plan the query, so it refuses.
    dsn = "postgresql://nobody:x@127.0.0.1:1/none"
    refused = CliRunner().invoke(cli, ["check", "delete from products", "--dsn", dsn])
    assert refused.exit_code == EXIT_REFUSED
    assert "✗ shape  NOT_A_SELECT" in refused.output
    unplanned = CliRunner().invoke(cli, ["check", "select 1", "--dsn", dsn])
    assert unplanned.exit_code == EXIT_REFUSED
    assert "✗ cost   COST_UNAVAILABLE: could not estimate the query's cost: could not connect" in (
        unplanned.output
    )
