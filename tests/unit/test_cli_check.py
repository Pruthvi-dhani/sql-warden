import re
from pathlib import Path

from click.testing import CliRunner

from sql_warden.cli import cli
from tests.unit.conftest import FakeEngine


def test_allowed_query_shows_each_check_and_executes_nothing(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["check", "select id from products"])
    assert outcome.exit_code == 0, outcome.output
    parse, shape, *rest = outcome.output.splitlines()
    assert re.fullmatch(r"✓ parse  \d+\.\d ms", parse)
    assert re.fullmatch(r"✓ shape  \d+\.\d ms", shape)
    assert rest == [
        "→ allowed (profile all; dry run, nothing was executed)",
        "  note: added LIMIT 101 (row cap 100 + 1 to detect truncation)",
        "  would run: SELECT id FROM products LIMIT 101",
    ]
    assert engines[0].executed == []


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


def test_check_does_not_connect_to_the_database() -> None:
    # The real engine, pointed at a port nothing listens on: a dry run must still work.
    outcome = CliRunner().invoke(
        cli, ["check", "select 1", "--dsn", "postgresql://nobody:x@127.0.0.1:1/none"]
    )
    assert outcome.exit_code == 0, outcome.output
