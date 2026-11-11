"""Lineage against the seeded warehouse: its columns are the columns Postgres returns."""

import pytest
import sqlglot
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from sql_warden.audit import MemoryAuditSink
from sql_warden.catalog import Catalog
from sql_warden.config import MaskRule
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.models import RefusalCode
from sql_warden.pipeline.lineage import trace
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
    assert allowed.result is not None  # not masked yet: applying the masks is 5.3

    refused = warden.run("select id from customers where ssn like '123%'").decision.refused_by
    assert refused is not None
    assert refused.refusal is not None
    assert refused.refusal.code == RefusalCode.MASKED_COLUMN_IN_PREDICATE
    computed = warden.check("select upper(email) from customers").refused_by
    assert computed is not None
    assert computed.refusal is not None
    assert computed.refusal.code == RefusalCode.MASKED_COLUMN_IN_EXPRESSION
    assert warden.check("select count(ssn) from customers").allowed
