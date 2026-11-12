"""Masking against the seeded warehouse: lineage's columns are the ones Postgres returns, and
the example config's support profile sees customers.ssn and email masked."""

import json
import uuid
from pathlib import Path
from typing import Any

import psycopg
import pytest
import sqlglot
from click.testing import CliRunner
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from sql_warden.audit import MemoryAuditSink
from sql_warden.catalog import Catalog
from sql_warden.cli import build_warden, cli
from sql_warden.config import MaskRule, load_config
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.models import RefusalCode
from sql_warden.pipeline.lineage import trace
from sql_warden.pipeline.masking import Hmac
from sql_warden.profiles import Access
from sql_warden.warden import Warden
from tests.integration.conftest import Warehouse

pytestmark = pytest.mark.integration

EMAIL = ("public", "customers", "email")
SSN = ("public", "customers", "ssn")


@pytest.mark.parametrize(
    ("sql", "masked"),
    [
        ("select * from customers", {"email": EMAIL, "ssn": SSN}),
        ("select id, ssn as s, email from customers", {"s": SSN, "email": EMAIL}),
        (
            "select c.*, o.* from customers c join orders o on o.customer_id = c.id",
            {"email": EMAIL, "ssn": SSN},
        ),
        ("select * from customers c join orders o using (id)", {"email": EMAIL, "ssn": SSN}),
        ("select o.*, c.ssn from orders o join customers c on c.id = o.customer_id", {"ssn": SSN}),
        ("with x as (select * from customers) select * from x", {"email": EMAIL, "ssn": SSN}),
        ("select * from (select ssn, id from customers) t", {"ssn": SSN}),
        ("select ssn from customers union all select ssn from customers", {"ssn": SSN}),
    ],
)
def test_the_outputs_are_the_columns_postgres_returns_in_order(
    warehouse: Warehouse, sql: str, masked: dict[str, tuple[str, str, str]]
) -> None:
    # 5.3 masks by position, so a column out of place would come back in the clear.
    engine = PostgresEngine(warehouse.reader_dsn, max_rows=1)
    tree = normalize_identifiers(sqlglot.parse_one(sql, dialect="postgres"), dialect="postgres")
    lineage = trace(tree, {EMAIL, SSN}, schema=Catalog(engine).schema())
    returned = engine.execute(sql).columns
    assert tuple(output.name for output in lineage.outputs) == returned
    marked = {
        output.name: next(iter(output.flow.columns))
        for output in lineage.outputs
        if output.flow.columns
    }
    assert marked == masked
    assert all(output.flow.unchanged for output in lineage.outputs)


def test_the_check_on_the_real_catalog(warehouse: Warehouse) -> None:
    warden = Warden(
        PostgresEngine(warehouse.reader_dsn, max_rows=5),
        audit=MemoryAuditSink(),
        profile="support",
        access=Access("*"),
        masks={EMAIL: MaskRule.model_validate("hmac"), SSN: MaskRule.model_validate("redact")},
        mask_key=DEMO_KEY,
    )
    allowed = warden.run("select id, email, ssn from customers where id <= 3 order by id")
    assert allowed.decision.allowed, allowed.decision.refused_by
    assert [step.check for step in allowed.decision.trace] == [
        "parse",
        "shape",
        "access",
        "masking",
        "cost",
    ]
    assert allowed.result is not None
    assert {row[2] for row in allowed.result.rows} == {"[REDACTED]"}

    refused = warden.run("select id from customers where ssn like '123%'").decision.refused_by
    assert refused is not None
    assert refused.refusal is not None
    assert refused.refusal.code == RefusalCode.MASKED_COLUMN_IN_PREDICATE
    computed = warden.check("select upper(email) from customers").refused_by
    assert computed is not None
    assert computed.refusal is not None
    assert computed.refusal.code == RefusalCode.MASKED_COLUMN_IN_EXPRESSION
    assert warden.check("select count(ssn) from customers").allowed


EXAMPLE_CONFIG = Path(__file__).parents[2] / "warden.example.yaml"
DEMO_KEY = b"demo-only-mask-key-not-for-real-use"


@pytest.fixture
def example(warehouse: Warehouse, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The example config, pointed at the test warehouse."""
    monkeypatch.delenv("WARDEN_MASK_KEY", raising=False)
    host_port = warehouse.reader_dsn.split("@")[1].split("/")[0]
    policy = tmp_path / "warden.yaml"
    policy.write_text(EXAMPLE_CONFIG.read_text().replace("localhost:5433", host_port))
    return policy


def _rows(policy: Path, profile: str, sql: str) -> tuple[tuple[Any, ...], ...]:
    outcome = build_warden(load_config(policy), profile, audit=MemoryAuditSink()).run(sql)
    assert outcome.result is not None, outcome.decision.refused_by or outcome.error
    rows: tuple[tuple[Any, ...], ...] = outcome.result.rows
    return rows


def test_support_sees_ssn_and_email_masked_where_admin_sees_them(example: Path) -> None:
    sql = "select id, email, phone, ssn from customers where id <= 3 order by id"
    clear = _rows(example, "admin", sql)
    masked = _rows(example, "support", sql)
    token = Hmac(DEMO_KEY).apply
    assert masked == tuple(
        (id_, token(email), "*" * (len(phone) - 4) + phone[-4:], "[REDACTED]")
        for id_, email, phone, _ in clear
    )
    for (_, email, phone, ssn), row in zip(clear, masked, strict=True):
        assert email not in row
        assert ssn not in row
        assert phone not in row


def test_select_star_is_masked_too(example: Path) -> None:
    (row,) = _rows(example, "support", "select * from customers where id = 7")
    (clear,) = _rows(example, "admin", "select * from customers where id = 7")
    assert len(row) == len(clear) == 7
    assert row[0] == clear[0]  # id
    assert row[4] == "[REDACTED]"  # ssn, by position
    assert row[2] == Hmac(DEMO_KEY).apply(clear[2])  # email


def test_tokens_match_across_queries_so_rows_can_be_matched(example: Path) -> None:
    first = dict(_rows(example, "support", "select id, email from customers where id <= 5"))
    second = dict(
        _rows(
            example,
            "support",
            "with c as (select id, email from customers) select id, email from c where id <= 5",
        )
    )
    assert first == second
    assert len(set(first.values())) == 5  # distinct customers, distinct tokens


def test_leaky_uses_are_refused_and_counting_is_not(example: Path) -> None:
    warden = build_warden(load_config(example), "support", audit=MemoryAuditSink())
    leaks = {
        "select id from customers where ssn like '123%'": "MASKED_COLUMN_IN_PREDICATE",
        "select email, count(*) from customers c join orders o on o.customer_id = c.id "
        "group by email": "MASKED_COLUMN_IN_PREDICATE",
        "select upper(email) from customers": "MASKED_COLUMN_IN_EXPRESSION",
        "select id from customers order by phone": "MASKED_COLUMN_IN_PREDICATE",
    }
    for sql, code in leaks.items():
        refused = warden.check(sql).refused_by
        assert refused is not None, sql
        assert refused.refusal is not None
        assert refused.refusal.code == code, sql
    (row,) = _rows(example, "support", "select count(distinct ssn) from customers")
    assert row == (10000,)


def test_the_audit_record_lists_the_masked_columns(
    example: Path, audit_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    sql = f"select id, ssn, email from customers where id = 1 -- {uuid.uuid4()}"
    monkeypatch.setenv("SQL_WARDEN_AUDIT_DSN", audit_dsn)
    outcome = CliRunner().invoke(
        cli, ["--config", str(example), "query", sql, "--profile", "support", "--json"]
    )
    assert outcome.exit_code == 0, outcome.output
    payload = json.loads(outcome.output)
    assert [m["column"] for m in payload["masked_columns"]] == ["ssn", "email"]
    assert payload["result"]["rows"][0][1] == "[REDACTED]"
    with psycopg.connect(audit_dsn) as conn:
        row = conn.execute(
            "SELECT masked_columns FROM audit_events WHERE sql = %s", (sql,)
        ).fetchone()
    assert row == (["ssn", "email"],)
