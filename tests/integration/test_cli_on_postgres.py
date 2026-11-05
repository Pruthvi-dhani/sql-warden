"""The CLI end to end against the seeded warehouse: what a script calling it sees."""

import json

import pytest
from click.testing import CliRunner

from sql_warden.cli import EXIT_ERROR, EXIT_REFUSED, cli
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration


def _invoke(warehouse: Warehouse, *args: str) -> tuple[int, str]:
    outcome = CliRunner().invoke(cli, list(args), env={"SQL_WARDEN_DSN": warehouse.reader_dsn})
    return outcome.exit_code, outcome.output


def test_an_allowed_query_runs_and_exits_0(warehouse: Warehouse) -> None:
    code, output = _invoke(warehouse, "query", "select id, name from products order by id")
    assert code == 0, output
    lines = output.splitlines()
    assert lines[:3] == ["id  | name", "----+------------", "1   | Product 1"]
    assert lines[-2].startswith("(100 rows, truncated at the row cap, ")
    assert lines[-1] == "note: added LIMIT 101 (row cap 100 + 1 to detect truncation)"


def test_a_refused_query_never_reaches_the_database_and_exits_2(warehouse: Warehouse) -> None:
    code, output = _invoke(
        warehouse, "query", "with x as (delete from orders returning *) select count(*) from x"
    )
    assert code == EXIT_REFUSED
    assert output.splitlines()[1:] == [
        "✗ shape  NOT_READ_ONLY: the query contains a DELETE in the CTE x; "
        "queries must not modify data",
        "→ refused by shape",
    ]
    code, output = _invoke(warehouse, "query", "select count(*) from orders")
    assert output.splitlines()[2] == "1000000"


def test_a_database_error_is_clean_and_exits_1(warehouse: Warehouse) -> None:
    code, output = _invoke(warehouse, "query", "select nope from products")
    assert code == EXIT_ERROR
    assert output.splitlines() == [
        'Error: column "nope" does not exist',
        "  SELECT nope FROM products LIMIT 101",
        "         ^",
        'HINT: Perhaps you meant to reference the column "products.name".',
    ]


def test_json_output_for_a_script(warehouse: Warehouse) -> None:
    code, output = _invoke(
        warehouse, "query", "select count(*) as n from customers", "--json", "--max-rows", "5"
    )
    assert code == 0, output
    payload = json.loads(output)
    assert payload["sql"] == "SELECT COUNT(*) AS n FROM customers LIMIT 6"
    assert payload["result"]["columns"] == ["n"]
    assert payload["result"]["rows"] == [[10000]]

    code, output = _invoke(warehouse, "query", "select 1 / 0", "--json")
    assert code == EXIT_ERROR
    assert json.loads(output)["error"] == "division by zero"
