import re

from click.testing import CliRunner

from sql_warden.cli import cli
from tests.unit.conftest import FakeEngine


def test_allowed_query_shows_each_check_and_executes_nothing(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["check", "select id from products"])
    assert outcome.exit_code == 0, outcome.output
    first, verdict = outcome.output.splitlines()
    assert re.fullmatch(r"✓ parse  \d+\.\d ms", first)
    assert verdict == "→ allowed (dry run, nothing was executed)"
    assert engines[0].executed == []


def test_refused_query_names_the_check_code_and_reason(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["check", "select * from orders where"])
    assert outcome.exit_code == 1
    assert outcome.output.splitlines()[0].startswith("✗ parse  PARSE_ERROR: ")
    assert outcome.output.splitlines()[-1] == "→ refused by parse"
    assert engines[0].executed == []


def test_empty_query_is_refused(engines: list[FakeEngine]) -> None:
    outcome = CliRunner().invoke(cli, ["check", "  ;  "])
    assert outcome.exit_code == 1
    assert "PARSE_ERROR: the query is empty" in outcome.output


def test_check_does_not_connect_to_the_database() -> None:
    # The real engine, pointed at a port nothing listens on: a dry run must still work.
    outcome = CliRunner().invoke(
        cli, ["check", "select 1", "--dsn", "postgresql://nobody:x@127.0.0.1:1/none"]
    )
    assert outcome.exit_code == 0, outcome.output
