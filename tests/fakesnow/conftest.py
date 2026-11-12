"""The Snowflake engine running real SQL, on fakesnow: Snowflake's connector over DuckDB.

fakesnow is not one of the project's dependencies. It pins sqlglot to an older release than
the checks are developed against, and needs a connector older than the current one, so it
gets an environment of its own, laid over the project's for one run:

    uv run --with 'fakesnow==0.12.1' --with 'snowflake-connector-python<5' pytest tests/fakesnow

Without fakesnow these tests are not collected at all, so a plain `pytest` neither runs nor
skips them. It is an emulator: it shows that what sql-warden generates runs as Snowflake SQL
and that the catalog is read as expected, not that Snowflake itself agrees. tests/snowflake
is for that.
"""

import importlib
import importlib.util
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from sql_warden.engines import CostEstimate
from sql_warden.engines.snowflake import SnowflakeEngine, cost_estimate

collect_ignore_glob = [] if importlib.util.find_spec("fakesnow") else ["test_*.py"]

DSN = "snowflake://WARDEN_READER:not-checked@test-account/warehouse/public?role=WARDEN_READER"
PLAN = json.loads(
    (Path(__file__).parents[1] / "unit/fixtures/snowflake_explain/pruned_scan.json").read_text()
)
# A small copy of the demo warehouse (dev/warehouse_seed.sql), as Snowflake would hold it.
SEED = [
    "create table customers (id int, full_name text, email text, phone text, ssn text)",
    "create table products (id int, name text, category text, price_cents int)",
    "create table orders (id int, customer_id int, product_id int, quantity int, tags variant)",
    "create table employee_salaries (id int, title text, salary_cents int)",
    'create table "MixedCase" ("Id" int, low text)',
    *(
        f"insert into customers values ({n}, 'Customer {n}', 'customer{n}@example.com', "
        f"'+1-555-{n:04d}', '{100 + n}-45-{6000 + n}')"
        for n in range(1, 13)
    ),
    *(
        f"insert into products values ({n}, 'Product {n}', "
        f"'{('Books', 'Games', 'Tools')[n % 3]}', {n * 250})"
        for n in range(1, 9)
    ),
    *(
        f"insert into orders select {n}, {n % 12 + 1}, {n % 8 + 1}, {n % 5 + 1}, "
        f'parse_json(\'["gift", "n{n % 3}"]\')'
        for n in range(1, 41)
    ),
    "insert into employee_salaries values (1, 'Engineer', 15000000), (2, 'Analyst', 9000000)",
    "insert into \"MixedCase\" values (1, 'a')",
]


@pytest.fixture
def warehouse(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """A seeded fake Snowflake behind snowflake.connector.connect; yields the DSN to use."""
    import snowflake.connector

    fakesnow = importlib.import_module("fakesnow")  # not a dependency: see above

    def explain(self: SnowflakeEngine, sql: str, *, tag: str | None = None) -> CostEstimate:
        # fakesnow has no planner: every query gets one saved plan, a pruned scan of 48 MiB.
        return cost_estimate(PLAN)

    monkeypatch.setattr(SnowflakeEngine, "explain", explain)
    with fakesnow.patch():
        admin = snowflake.connector.connect(database="WAREHOUSE", schema="PUBLIC")
        cursor = admin.cursor()
        for statement in SEED:
            cursor.execute(statement)
        yield DSN
