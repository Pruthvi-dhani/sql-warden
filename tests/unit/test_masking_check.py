"""The masking check in the Warden: uses that leak a masked column are refused."""

import pytest

from sql_warden.audit import MemoryAuditSink
from sql_warden.config import MaskRule
from sql_warden.engines import EngineUnavailable
from sql_warden.models import Decision, RefusalCode
from sql_warden.profiles import Access
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine
from tests.unit.test_lineage import CATALOG, EMAIL, SSN

EVERYTHING = Access("*")
REDACT = MaskRule.model_validate("redact")
MASKS = {EMAIL: MaskRule.model_validate("hmac"), SSN: REDACT}
EMAIL_IN_PREDICATES = {
    EMAIL: MaskRule.model_validate({"strategy": "hmac", "allow_in_predicates": True}),
    SSN: REDACT,
}


def _warden(
    masks: dict[tuple[str, str, str], MaskRule] | None = None,
    *,
    engine: FakeEngine | None = None,
    access: Access | None = EVERYTHING,
) -> Warden:
    return Warden(
        engine or FakeEngine(catalog=CATALOG),
        audit=MemoryAuditSink(),
        profile="public",
        access=access,
        masks=MASKS if masks is None else masks,
    )


def _refusal(decision: Decision) -> tuple[str, str, str]:
    refused = decision.refused_by
    assert refused is not None
    assert refused.refusal is not None
    return refused.check, refused.refusal.code, refused.refusal.reason


def test_it_runs_after_access_and_before_cost() -> None:
    decision = _warden().check("select id, email from customers")
    assert decision.allowed
    assert [step.check for step in decision.trace] == [
        "parse",
        "shape",
        "access",
        "masking",
        "cost",
    ]


def test_a_profile_without_masks_has_no_masking_check() -> None:
    decision = _warden({}).check("select id from customers where ssn like '1%'")
    assert decision.allowed
    assert [step.check for step in decision.trace] == ["parse", "shape", "access", "cost"]


def test_a_masked_column_in_a_predicate_is_refused() -> None:
    check, code, reason = _refusal(_warden().check("select id from customers where ssn like '1%'"))
    assert (check, code) == ("masking", RefusalCode.MASKED_COLUMN_IN_PREDICATE)
    assert reason == (
        "column ssn of public.customers is masked for profile public, so the query can't use "
        "it in WHERE: filtering, joining, grouping or sorting on it would reveal what the mask "
        "hides. Select it on its own, or leave it out"
    )


@pytest.mark.parametrize(
    ("sql", "clause"),
    [
        ("select o.id from orders o join customers c on c.email = o.note", "JOIN"),
        ("select email, count(*) from customers group by email", "GROUP BY"),
        ("select id from customers order by ssn", "ORDER BY"),
        ("select distinct ssn from customers", "DISTINCT"),
        ("select ssn from customers intersect select '123-45-6789'", "INTERSECT"),
    ],
)
def test_the_reason_names_the_clause(sql: str, clause: str) -> None:
    _, code, reason = _refusal(_warden().check(sql))
    assert code == RefusalCode.MASKED_COLUMN_IN_PREDICATE
    assert f"so the query can't use it in {clause}: " in reason


def test_a_masked_column_in_an_expression_is_refused() -> None:
    check, code, reason = _refusal(_warden().check("select upper(email) from customers"))
    assert (check, code) == ("masking", RefusalCode.MASKED_COLUMN_IN_EXPRESSION)
    assert reason == (
        "column email of public.customers is masked for profile public, so it can't be part "
        "of an expression (UPPER(customers.email)). Select it on its own, or count it with "
        "COUNT(email)"
    )


@pytest.mark.parametrize(
    "sql",
    [
        "select id, email, ssn from customers where id < 10 order by full_name",
        "select * from customers",
        "with x as (select email e from customers) select e from x",
        "select count(ssn), count(distinct email) from customers",
        "select email from customers union all select email from customers",
        "select name from products",
    ],
)
def test_selecting_it_as_it_is_or_counting_it_is_allowed(sql: str) -> None:
    decision = _warden().check(sql)
    assert decision.allowed, decision.refused_by


def test_what_runs_is_the_query_as_written() -> None:
    # The copy with every star expanded is only for following columns.
    decision = _warden().check("select * from customers")
    assert decision.sql == "SELECT * FROM public.customers LIMIT 101"


def test_nothing_is_planned_or_run_for_a_refused_query() -> None:
    engine = FakeEngine(catalog=CATALOG)
    outcome = _warden(engine=engine).run("select id from customers where ssn = '123-45-6789'")
    assert outcome.result is None
    assert (engine.explained, engine.executed) == ([], [])


def test_the_access_check_still_comes_first() -> None:
    narrow = Access({("public", "customers"): frozenset({"id", "email"})})
    check, code, _ = _refusal(_warden(access=narrow).check("select id from customers order by ssn"))
    assert (check, code) == ("access", RefusalCode.COLUMN_NOT_ALLOWED)


class TestAllowInPredicates:
    """A column that is hidden but not secret: an hmac'd email that reports group by."""

    @pytest.mark.parametrize(
        "sql",
        [
            "select email, count(*) from customers group by email order by email",
            "select o.id from orders o join customers c on c.email = o.note",
            "select id from customers where email like '%@example.com'",
            "select distinct email from customers",
            "select upper(email) from customers",
        ],
    )
    def test_it_can_be_filtered_joined_grouped_sorted_and_computed_with(self, sql: str) -> None:
        decision = _warden(EMAIL_IN_PREDICATES).check(sql)
        assert decision.allowed, decision.refused_by

    def test_other_columns_keep_the_default(self) -> None:
        _, code, reason = _refusal(
            _warden(EMAIL_IN_PREDICATES).check(
                "select email from customers where ssn > '5' order by email"
            )
        )
        assert code == RefusalCode.MASKED_COLUMN_IN_PREDICATE
        assert "column ssn of public.customers" in reason

    def test_an_expression_over_both_needs_both(self) -> None:
        _, code, reason = _refusal(
            _warden(EMAIL_IN_PREDICATES).check("select email || ssn from customers")
        )
        assert code == RefusalCode.MASKED_COLUMN_IN_EXPRESSION
        assert "column ssn of public.customers" in reason

    def test_the_default_is_off(self) -> None:
        assert REDACT.allow_in_predicates is False


class TestFailClosed:
    def test_a_query_that_cant_be_followed_is_refused(self) -> None:
        check, code, reason = _refusal(
            _warden().check("select * from customers c, unnest(array[1, 2])")
        )
        assert (check, code) == ("masking", RefusalCode.MASKED_COLUMN_IN_EXPRESSION)
        assert reason.startswith(
            "profile public has masked columns, and could not tell which columns * returns here"
        )

    def test_without_the_catalog_nothing_can_be_followed(self) -> None:
        engine = FakeEngine(error=EngineUnavailable("could not connect to the database"))
        check, code, reason = _refusal(
            _warden(engine=engine, access=None).check("select id from customers")
        )
        assert (check, code) == ("masking", RefusalCode.CATALOG_UNAVAILABLE)
        assert reason == (
            "could not read the tables and columns to follow the masked ones: "
            "could not connect to the database"
        )
