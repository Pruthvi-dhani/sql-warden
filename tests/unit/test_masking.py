"""The mask strategies, on every kind of value a database returns."""

import datetime
import hashlib
import hmac
import uuid
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from sql_warden.config import ConfigError, MaskRule, parse_config
from sql_warden.pipeline.masking import (
    REDACTED,
    Hmac,
    Mask,
    Null,
    Partial,
    Redact,
    build_mask,
    canonical,
)

KEY = b"a-test-key-of-32-bytes-or-so!!!!"
OTHER_KEY = b"another-key-of-the-same-length!!"
UTC = datetime.UTC
EVERY_KIND = [
    "customer1@example.com",
    "",
    42,
    -7,
    3.14,
    Decimal("19.99"),
    True,
    False,
    datetime.date(2026, 11, 11),
    datetime.datetime(2026, 11, 11, 9, 30, tzinfo=UTC),
    datetime.time(9, 30),
    datetime.timedelta(hours=2),
    uuid.UUID("12345678-1234-5678-1234-567812345678"),
    b"\x00\xff",
    memoryview(b"abc"),
    [1, 2, 3],
    {"plan": "pro", "seats": 5},
]


class TestRedact:
    @pytest.mark.parametrize("value", EVERY_KIND)
    def test_every_value_becomes_the_same_text(self, value: object) -> None:
        assert Redact().apply(value) == "[REDACTED]"

    def test_a_missing_value_stays_missing(self) -> None:
        assert Redact().apply(None) is None

    def test_the_text_can_be_chosen(self) -> None:
        assert Redact("***").apply("123-45-6789") == "***"


class TestPartial:
    @pytest.mark.parametrize(
        ("mask", "value", "seen"),
        [
            (Partial(), "555-123-4567", "********4567"),
            (Partial(), "123-45-6789", "*******6789"),
            (Partial(keep_last=2), "123-45-6789", "*********89"),
            (Partial(keep_first=2, keep_last=0), "123-45-6789", "12*********"),
            (Partial(keep_first=1, keep_last=4), "customer1@example.com", "c****************.com"),
            (Partial(), 4111111111111111, "************1111"),
            (Partial(), Decimal("1234567.89"), "******7.89"),
            (Partial(), datetime.date(2026, 11, 11), "******1-11"),
            (Partial(), uuid.UUID("12345678-1234-5678-1234-567812345678"), "*" * 32 + "5678"),
            (Partial(), "żółć-1234-5678", "**********5678"),  # characters, not bytes
        ],
    )
    def test_the_ends_stay_and_the_rest_is_starred(
        self, mask: Partial, value: object, seen: str
    ) -> None:
        assert mask.apply(value) == seen
        assert len(seen) == len(str(value))  # the length shows

    @pytest.mark.parametrize(
        ("value", "seen"),
        [
            ("12345678", "****5678"),  # exactly half: shown
            ("1234567", "*******"),  # 4 of 7 would be more than half
            ("12345", "*****"),
            ("1234", "****"),
            ("12", "**"),
            ("", ""),
            (1234, "****"),
        ],
    )
    def test_never_more_than_half_of_a_value(self, value: object, seen: str) -> None:
        assert Partial().apply(value) == seen

    @pytest.mark.parametrize(
        "value",
        [True, False, b"\x00\xff", bytearray(b"ab"), memoryview(b"abc"), [1, 2], (1, 2), {}],
    )
    def test_values_their_length_or_shape_would_give_away_are_redacted(self, value: object) -> None:
        # "****" against "*****" would tell true from false.
        assert Partial().apply(value) == REDACTED

    def test_a_missing_value_stays_missing(self) -> None:
        assert Partial().apply(None) is None

    @pytest.mark.parametrize(
        ("settings", "message"),
        [
            ({"keep_first": 0, "keep_last": 0}, "keeps nothing is a redaction"),
            ({"keep_first": -1}, "must not be negative"),
            ({"keep_last": -4}, "must not be negative"),
        ],
    )
    def test_settings_that_make_no_sense(self, settings: dict[str, int], message: str) -> None:
        with pytest.raises(ValueError, match=message):
            Partial(**settings)


class TestHmac:
    def test_the_same_value_and_key_always_give_the_same_token(self) -> None:
        tokens = {Hmac(KEY).apply("customer1@example.com") for _ in range(3)}
        assert len(tokens) == 1
        (token,) = tokens
        assert isinstance(token, str)
        assert len(token) == 16
        assert int(token, 16) >= 0  # hex

    def test_it_is_the_hmac_sha256_of_the_value(self) -> None:
        full = hmac.new(KEY, b"customer1@example.com", hashlib.sha256).hexdigest()
        assert Hmac(KEY).apply("customer1@example.com") == full[:16]

    def test_another_key_gives_another_token(self) -> None:
        assert Hmac(KEY).apply("customer1@example.com") != Hmac(OTHER_KEY).apply(
            "customer1@example.com"
        )

    def test_different_values_give_different_tokens(self) -> None:
        tokens = [Hmac(KEY).apply(value) for value in EVERY_KIND]
        assert len(set(tokens)) == len(EVERY_KIND)
        assert Hmac(KEY).apply("a@example.com") != Hmac(KEY).apply("A@example.com")

    @pytest.mark.parametrize(
        "same",
        [
            [42, "42", 42.0, Decimal("42"), Decimal("42.00")],
            [1.5, Decimal("1.50"), "1.5"],
            [Decimal("100"), 100, Decimal("1E+2")],
            [
                datetime.datetime(2026, 11, 11, 9, 30, tzinfo=UTC),
                datetime.datetime(
                    2026, 11, 11, 15, 0, tzinfo=datetime.timezone(datetime.timedelta(hours=5.5))
                ),
            ],
            [b"\x00\xff", bytearray(b"\x00\xff"), memoryview(b"\x00\xff"), "00ff"],
            [
                uuid.UUID("12345678-1234-5678-1234-567812345678"),
                "12345678-1234-5678-1234-567812345678",
            ],
            [{"a": 1, "b": [2.0]}, {"b": [2], "a": Decimal("1.0")}],
            [[1, 2], (1, 2)],
        ],
    )
    def test_equal_values_match_however_the_database_typed_them(self, same: list[Any]) -> None:
        # So a token can be matched across columns, as the values could.
        assert len({Hmac(KEY).apply(value) for value in same}) == 1

    def test_but_not_values_that_only_look_alike(self) -> None:
        mask = Hmac(KEY)
        assert mask.apply(True) != mask.apply(1)
        assert mask.apply([1, 2]) != mask.apply([2, 1])
        assert mask.apply(["a,b"]) != mask.apply(["a", "b"])
        assert mask.apply(0.1) != mask.apply(0.10000001)

    def test_a_missing_value_stays_missing(self) -> None:
        assert Hmac(KEY).apply(None) is None

    def test_a_short_key_is_refused(self) -> None:
        with pytest.raises(ValueError, match="at least 16 bytes"):
            Hmac(b"too-short")

    def test_the_key_is_never_shown(self) -> None:
        assert repr(Hmac(KEY)) == "Hmac()"

    def test_odd_numbers_have_one_text_too(self) -> None:
        assert canonical(float("nan")) == "nan"
        assert canonical(float("inf")) == "inf"
        assert canonical(Decimal("NaN")) == "NaN"
        assert canonical(10**30) == "1" + "0" * 30
        assert canonical(1e30) == "1" + "0" * 30
        assert canonical(Decimal("1E+30")) == "1" + "0" * 30
        assert canonical(0.1) == canonical(Decimal("0.10")) == "0.1"
        assert canonical(-0.0) == canonical(Decimal("-0.00")) == canonical(0) == "0"
        assert canonical(1e-7) == "0.0000001"


class TestNull:
    @pytest.mark.parametrize("value", [*EVERY_KIND, None])
    def test_nothing_is_returned(self, value: object) -> None:
        assert Null().apply(value) is None


class TestRules:
    @pytest.mark.parametrize(
        ("rule", "mask"),
        [
            ("redact", Redact()),
            ({"strategy": "redact", "text": "***"}, Redact("***")),
            ("partial", Partial(keep_last=4)),
            ({"strategy": "partial", "keep_last": 2}, Partial(keep_last=2)),
            ({"strategy": "partial", "keep_first": 3}, Partial(keep_first=3, keep_last=0)),
            (
                {"strategy": "partial", "keep_first": 1, "keep_last": 4},
                Partial(keep_first=1, keep_last=4),
            ),
            ("hmac", Hmac(KEY)),
            ("null", Null()),
        ],
    )
    def test_a_rule_as_warden_yaml_will_write_it(self, rule: object, mask: Mask) -> None:
        assert build_mask(MaskRule.model_validate(rule), key=KEY) == mask

    def test_every_mask_names_its_strategy(self) -> None:
        masks: list[Mask] = [Redact(), Partial(), Hmac(KEY), Null()]
        assert [mask.name for mask in masks] == ["redact", "partial", "hmac", "null"]

    def test_hmac_needs_a_key(self) -> None:
        with pytest.raises(ValueError, match="an hmac mask needs a key"):
            build_mask(MaskRule.model_validate("hmac"))
        assert build_mask(MaskRule.model_validate("redact")) == Redact()  # the others don't

    @pytest.mark.parametrize(
        ("rule", "message"),
        [
            ("scramble", "Input should be 'redact', 'partial', 'hmac' or 'null'"),
            (
                {"strategy": "redact", "keep_last": 4},
                "keep_last is for the partial strategy, not redact",
            ),
            (
                {"strategy": "hmac", "keep_first": 1},
                "keep_first is for the partial strategy, not hmac",
            ),
            ({"strategy": "hmac", "text": "x"}, "text is for the redact strategy, not hmac"),
            (
                {"strategy": "partial", "keep_first": 0, "keep_last": 0},
                "a partial mask that keeps nothing is a redaction: use redact",
            ),
            ({"strategy": "partial", "keep_last": -1}, "greater than or equal to 0"),
            ({"strategy": "hmac", "key": "inline"}, "Extra inputs are not permitted"),
            ({"keep_last": 4}, "Field required"),
        ],
    )
    def test_rules_that_make_no_sense(self, rule: object, message: str) -> None:
        with pytest.raises(ValidationError) as caught:
            MaskRule.model_validate(rule)
        assert message in str(caught.value)


def test_warden_yaml_takes_no_masks_until_they_are_applied() -> None:
    # A mask in the file that nothing enforces would leave the column in the clear. The
    # section opens in 5.3, with the code that masks results.
    text = "version: 1\nprofiles:\n  p:\n    masks:\n      public.customers.ssn: redact\n"
    with pytest.raises(ConfigError, match=r"profiles\.p\.masks: Extra inputs are not permitted"):
        parse_config(text)
