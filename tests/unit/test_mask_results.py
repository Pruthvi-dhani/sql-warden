"""Masks applied to results: by the Warden, reported in responses, the CLI and the audit log."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from sql_warden.audit import MemoryAuditSink
from sql_warden.cli import cli
from sql_warden.config import ConfigError, MaskRule, parse_config
from sql_warden.engines import Result
from sql_warden.models import MaskedOutput
from sql_warden.pipeline.masking import Hmac
from sql_warden.profiles import Access, select_profile
from sql_warden.render import format_decision
from sql_warden.server import describe
from sql_warden.warden import Warden
from tests.unit.conftest import FakeEngine
from tests.unit.test_lineage import CATALOG, EMAIL, SSN
from tests.unit.test_masking import KEY

PHONE = ("public", "customers", "phone")
RULES = {
    EMAIL: MaskRule.model_validate("hmac"),
    PHONE: MaskRule.model_validate("partial"),
    SSN: MaskRule.model_validate("redact"),
}
ROWS = Result(
    columns=("id", "email", "phone", "ssn"),
    rows=(
        (1, "customer1@example.com", "555-010-0001", "123-45-6789"),
        (2, "customer2@example.com", None, None),
    ),
    truncated=False,
    duration_ms=1.0,
)


def _warden(
    result: Result = ROWS,
    rules: dict[tuple[str, str, str], MaskRule] | None = None,
    sink: MemoryAuditSink | None = None,
) -> Warden:
    return Warden(
        FakeEngine(catalog=CATALOG, result=result),
        audit=sink or MemoryAuditSink(),
        profile="support",
        access=Access("*"),
        masks=RULES if rules is None else rules,
        mask_key=KEY,
    )


class TestTheRows:
    def test_each_masked_column_gets_its_own_mask(self) -> None:
        outcome = _warden().run("select id, email, phone, ssn from customers")
        assert outcome.result is not None
        token = Hmac(KEY).apply
        assert outcome.result.rows == (
            (1, token("customer1@example.com"), "********0001", "[REDACTED]"),
            (2, token("customer2@example.com"), None, None),
        )
        assert outcome.result.columns == ROWS.columns  # names and order untouched

    def test_by_position_whatever_the_names(self) -> None:
        result = Result(("a", "b"), (("x@example.com", 7),), truncated=False, duration_ms=1.0)
        outcome = _warden(result).run("select email as a, id as b from customers")
        assert outcome.result is not None
        assert outcome.result.rows == ((Hmac(KEY).apply("x@example.com"), 7),)

    def test_the_same_value_gives_the_same_token_in_every_query(self) -> None:
        first = _warden().run("select id, email, phone, ssn from customers")
        second = _warden().run("select id, email, phone, ssn from customers where id < 3")
        assert first.result is not None
        assert second.result is not None
        assert first.result.rows[0][1] == second.result.rows[0][1]

    def test_a_query_that_reads_no_masked_column_is_untouched(self) -> None:
        result = Result(("id", "full_name"), ((1, "Ada"),), truncated=False, duration_ms=1.0)
        outcome = _warden(result).run("select id, full_name from customers")
        assert outcome.result == result
        assert outcome.decision.masked == ()

    def test_a_profile_without_masks_sees_everything(self) -> None:
        outcome = _warden(rules={}).run("select id, email, phone, ssn from customers")
        assert outcome.result == ROWS


class TestComputedOrMixedColumns:
    """Hidden whole: no one column's mask fits them."""

    def test_a_union_all_of_two_masked_columns(self) -> None:
        result = Result(("email",), (("a@example.com",), ("123-45-6789",)), False, 1.0)
        outcome = _warden(result).run(
            "select email from customers union all select ssn from customers"
        )
        assert outcome.result is not None
        assert outcome.result.rows == (("[REDACTED]",), ("[REDACTED]",))
        (masked,) = outcome.decision.masked
        assert masked == MaskedOutput(
            0, "email", "redact", ("public.customers.email", "public.customers.ssn"), computed=True
        )

    def test_with_a_null_mask_among_them_they_are_null(self) -> None:
        rules = {**RULES, SSN: MaskRule.model_validate("null")}
        result = Result(("email",), (("a@example.com",), (None,)), False, 1.0)
        outcome = _warden(result, rules).run(
            "select email from customers union all select ssn from customers"
        )
        assert outcome.result is not None
        assert outcome.result.rows == ((None,), (None,))

    def test_an_expression_the_rule_allows_still_comes_back_hidden(self) -> None:
        rules = {EMAIL: MaskRule.model_validate({"strategy": "hmac", "allow_in_predicates": True})}
        result = Result(("domain",), (("example.com",),), False, 1.0)
        outcome = _warden(result, rules).run(
            "select split_part(email, '@', 2) as domain from customers"
        )
        assert outcome.decision.allowed, outcome.decision.refused_by
        assert outcome.result is not None
        assert outcome.result.rows == (("[REDACTED]",),)


class TestFailClosed:
    def test_a_result_with_other_columns_than_expected_returns_nothing(self) -> None:
        # Masks go by position: one column out of place could put an SSN where an id was.
        result = Result(("id", "email"), ((1, "a@example.com"),), False, 1.0)
        outcome = _warden(result).run("select id, email, phone, ssn from customers")
        assert outcome.result is None
        assert outcome.error is not None
        assert str(outcome.error) == (
            "the result has 2 columns where 4 were expected, so its masked columns can't be "
            "found; nothing is returned"
        )

    def test_an_hmac_mask_needs_a_key(self) -> None:
        with pytest.raises(ValueError, match="an hmac mask needs a key"):
            Warden(FakeEngine(), audit=MemoryAuditSink(), masks=RULES)


class TestWhereItShows:
    def test_the_decision_and_the_response(self) -> None:
        decision = _warden().check("select id, ssn as s, email from customers")
        assert decision.masked == (
            MaskedOutput(1, "s", "redact", ("public.customers.ssn",)),
            MaskedOutput(2, "email", "hmac", ("public.customers.email",)),
        )
        response = describe(decision)
        assert [m.model_dump() for m in response.masked_columns] == [
            {
                "column": "s",
                "position": 1,
                "strategy": "redact",
                "sources": ["public.customers.ssn"],
            },
            {
                "column": "email",
                "position": 2,
                "strategy": "hmac",
                "sources": ["public.customers.email"],
            },
        ]

    def test_the_audit_record(self) -> None:
        sink = MemoryAuditSink()
        _warden(sink=sink).run("select id, email, phone, ssn from customers")
        _warden(sink=sink).check("select ssn from customers")
        _warden(sink=sink).run("select id from customers")
        assert [event.masked_columns for event in sink.events] == [
            ("email", "phone", "ssn"),
            ("ssn",),
            (),
        ]

    def test_the_cli_decision(self) -> None:
        decision = _warden().check("select id, ssn from customers")
        lines = format_decision(decision, dry_run=True).splitlines()
        assert "  masked: ssn (redact)" in lines


POLICY = """\
version: 1
default_profile: support
masking:
  key: a-test-key-of-32-bytes-or-so!!!!
profiles:
  support:
    tables:
      public.customers: "*"
      public.products: [id, name]
    masks:
      public.customers.ssn: redact
      public.customers.email: {strategy: hmac, allow_in_predicates: true}
  admin:
    tables: "*"
"""


class TestConfig:
    def test_a_profile_gets_its_masks_and_another_none(self) -> None:
        config = parse_config(POLICY)
        support, admin = select_profile(config, "support"), select_profile(config, "admin")
        assert support.masks == {
            SSN: MaskRule(strategy="redact"),
            EMAIL: MaskRule(strategy="hmac", allow_in_predicates=True),
        }
        assert admin.masks == {}

    def test_the_key_is_never_shown(self) -> None:
        config = parse_config(POLICY)
        assert "a-test-key" not in repr(config)
        assert "a-test-key" not in str(config.model_dump())

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            (
                "profiles:\n  p:\n    tables: '*'\n    masks:\n"
                "      public.customers.email: hmac\n",
                "profile p masks public.customers.email with hmac, which needs masking.key "
                "(set it from the environment: key: ${WARDEN_MASK_KEY})",
            ),
            ("masking:\n  key: too-short\n", "masking.key: must be at least 16 bytes"),
            (
                "profiles:\n  p:\n    tables:\n      public.products: [id]\n    masks:\n"
                "      public.customers.ssn: redact\n",
                "profiles.p: masks public.customers.ssn, but the profile doesn't read "
                "public.customers",
            ),
            (
                "profiles:\n  p:\n    tables:\n      public.customers: [id, email]\n    masks:\n"
                "      public.customers.ssn: redact\n",
                "profiles.p: masks public.customers.ssn, but the profile doesn't read column ssn "
                "of public.customers",
            ),
            (
                "profiles:\n  p:\n    tables: '*'\n    masks:\n      customers.ssn: redact\n",
                "profiles.p.masks: 'customers.ssn' must be schema.table.column, "
                "e.g. public.customers.ssn",
            ),
            (
                "profiles:\n  p:\n    tables: '*'\n    masks:\n      public.customers.ssn: hide\n",
                "Input should be 'redact', 'partial', 'hmac' or 'null'",
            ),
        ],
    )
    def test_problems(self, text: str, message: str) -> None:
        with pytest.raises(ConfigError) as caught:
            parse_config("version: 1\n" + text)
        assert message in str(caught.value)

    def test_the_key_can_come_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WARDEN_MASK_KEY", "from-the-environment-0123456789")
        config = parse_config("version: 1\nmasking:\n  key: ${WARDEN_MASK_KEY}\n")
        assert config.masking.key is not None
        assert config.masking.key.get_secret_value() == "from-the-environment-0123456789"
        monkeypatch.delenv("WARDEN_MASK_KEY")
        with pytest.raises(ConfigError, match="environment variable WARDEN_MASK_KEY is not set"):
            parse_config("version: 1\nmasking:\n  key: ${WARDEN_MASK_KEY}\n")


class TestCli:
    @pytest.fixture
    def policy(self, isolated_cli: Path) -> Path:
        path = isolated_cli / "warden.yaml"
        path.write_text(POLICY)
        return path

    def test_query_masks_the_rows_and_says_so(
        self, engines: list[FakeEngine], policy: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(FakeEngine, "tables", lambda self: CATALOG)
        monkeypatch.setattr(FakeEngine, "execute", lambda self, sql: ROWS)
        outcome = CliRunner().invoke(cli, ["query", "select id, email, phone, ssn from customers"])
        assert outcome.exit_code == 0, outcome.output
        assert "123-45-6789" not in outcome.output
        assert "customer1@example.com" not in outcome.output
        assert "[REDACTED]" in outcome.output
        lines = outcome.output.splitlines()
        assert "masked: email (hmac)" in lines
        assert "masked: ssn (redact)" in lines

    def test_tables_marks_the_masked_columns(
        self, engines: list[FakeEngine], policy: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(FakeEngine, "tables", lambda self: CATALOG)
        outcome = CliRunner().invoke(cli, ["tables", "customers"])
        assert outcome.exit_code == 0, outcome.output
        assert "  ssn        text  masked: redact" in outcome.output.splitlines()
        assert "  email      text  masked: hmac" in outcome.output.splitlines()
        assert "  full_name  text" in outcome.output.splitlines()

    def test_validate_lists_the_masks_never_the_key(self, policy: Path) -> None:
        outcome = CliRunner().invoke(cli, ["config", "validate"])
        assert outcome.exit_code == 0, outcome.output
        lines = outcome.output.splitlines()
        assert "  masking:   hmac key set" in lines
        assert "               masks public.customers.ssn (redact)" in lines
        assert (
            "               masks public.customers.email (hmac, may be filtered and joined on)"
            in lines
        )
        assert "a-test-key" not in outcome.output
