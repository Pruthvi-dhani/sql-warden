"""Mask strategies: what a profile sees in place of a sensitive column's values.

    redact   a fixed text                           [REDACTED]
    partial  the ends kept, the rest starred        ********4567
    hmac     a keyed, repeatable token              3f9a1c0b7e2d4a61
    null     nothing

Masks run on result values after the query, so the database joins, filters and groups on the
real values. A missing value (NULL) stays missing under redact, partial and hmac: whether there
is a value is not hidden. Use null to hide that too.
"""

import datetime
import hashlib
import hmac
import json
import math
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Protocol

from sql_warden.catalog import Catalog
from sql_warden.config import MaskRule
from sql_warden.engines import EngineError
from sql_warden.models import Refusal, RefusalCode
from sql_warden.pipeline.access import DEFAULT_SCHEMAS
from sql_warden.pipeline.base import CheckContext
from sql_warden.pipeline.lineage import LineageError, MaskedColumn, Use, trace

REDACTED = "[REDACTED]"
MIN_KEY_BYTES = 16
TOKEN_HEX_CHARS = 16
"""64 bits of the HMAC: among a million distinct values, the chance that any two share a token
is about 1 in 40 million."""


class Mask(Protocol):
    name: str

    def apply(self, value: object) -> object:
        """What the caller sees instead of value."""
        ...


@dataclass(frozen=True)
class Redact:
    """Every value becomes the same text, whatever its type."""

    text: str = REDACTED
    name = "redact"

    def apply(self, value: object) -> object:
        return None if value is None else self.text


@dataclass(frozen=True)
class Partial:
    """Keeps the first and last few characters and stars the rest: enough to recognise a
    value by, not to use it. The length shows.

    It never shows more than half of a value: one too short for that is starred entirely.
    Values whose length or shape would give them away (booleans, binary data, arrays, JSON)
    are redacted instead."""

    keep_first: int = 0
    keep_last: int = 4
    name = "partial"

    def __post_init__(self) -> None:
        if self.keep_first < 0 or self.keep_last < 0:
            raise ValueError("keep_first and keep_last must not be negative")
        if self.keep_first + self.keep_last == 0:
            raise ValueError("a partial mask that keeps nothing is a redaction: use redact")

    def apply(self, value: object) -> object:
        if value is None:
            return None
        if isinstance(value, bool | bytes | bytearray | memoryview | list | tuple | dict):
            return REDACTED
        text = str(value)
        kept = self.keep_first + self.keep_last
        if kept * 2 > len(text):
            return "*" * len(text)
        return (
            text[: self.keep_first] + "*" * (len(text) - kept) + text[len(text) - self.keep_last :]
        )


@dataclass(frozen=True)
class Hmac:
    """A keyed token: the same value always gives the same token, so results can still be
    matched, counted and grouped by it, and without the key a token can't be turned back or
    checked against a guess.

    Tokens match across columns and tables, like the values they stand for: 42 and '42' and
    42.0 give one token. Whoever holds the key can test guesses, so it is a secret."""

    key: bytes = field(repr=False)
    name = "hmac"

    def __post_init__(self) -> None:
        if len(self.key) < MIN_KEY_BYTES:
            raise ValueError(f"the hmac key must be at least {MIN_KEY_BYTES} bytes")

    def apply(self, value: object) -> object:
        if value is None:
            return None
        digest = hmac.new(self.key, canonical(value).encode(), hashlib.sha256).hexdigest()
        return digest[:TOKEN_HEX_CHARS]


@dataclass(frozen=True)
class Null:
    """Every value is withheld, including whether there was one."""

    name = "null"

    def apply(self, value: object) -> object:
        return None


def canonical(value: object) -> str:
    """One text per value, however the database typed it, so equal values get equal tokens:
    42, 42.0 and Decimal('42.00') are all "42"."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # Through its shortest decimal text, so 0.1 is "0.1" and 1e30 is a 1 and thirty 0s.
        return canonical(Decimal(repr(value))) if math.isfinite(value) else repr(value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            return str(value)
        return "0" if value == 0 else format(value.normalize(), "f")
    if isinstance(value, datetime.datetime):
        if value.tzinfo is not None:  # one instant, one text, whatever zone it came in
            value = value.astimezone(datetime.UTC)
        return value.isoformat()
    if isinstance(value, datetime.date | datetime.time):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).hex()
    if isinstance(value, list | tuple | dict):
        return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"))
    return str(value)


def _plain(value: object) -> object:
    """Arrays and JSON with every value inside in its canonical text."""
    if value is None:
        return None
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    return canonical(value)


def build_mask(rule: MaskRule, *, key: bytes | None = None) -> Mask:
    """The mask a rule in warden.yaml asks for. key is the hmac key, needed only by hmac."""
    if rule.strategy == "redact":
        return Redact(rule.text) if rule.text is not None else Redact()
    if rule.strategy == "partial":
        return Partial(keep_first=rule.keep_first or 0, keep_last=rule.keep_last or 0)
    if rule.strategy == "hmac":
        if key is None:
            raise ValueError("an hmac mask needs a key")
        return Hmac(key)
    return Null()


class MaskingCheck:
    """Refuses queries that would use a masked column where its values could leak, and works
    out which of the result's columns to mask."""

    name = "masking"

    def __init__(
        self,
        catalog: Catalog,
        masks: Mapping[MaskedColumn, MaskRule],
        *,
        profile: str,
        dialect: str = "postgres",
    ) -> None:
        self._catalog = catalog
        self.masks = dict(masks)
        self._profile = profile
        self._dialect = dialect

    def run(self, ctx: CheckContext) -> Refusal | None:
        try:
            lineage = trace(
                ctx.statements[0],
                self.masks,
                schema=self._catalog.schema(),
                dialect=self._dialect,
                default_schema=DEFAULT_SCHEMAS[self._dialect],
            )
        except EngineError as exc:
            return Refusal(
                RefusalCode.CATALOG_UNAVAILABLE,
                f"could not read the tables and columns to follow the masked ones: {exc}",
            )
        except LineageError as exc:
            # Fail closed: a query whose masked columns can't be followed doesn't run.
            return Refusal(
                RefusalCode.MASKED_COLUMN_IN_EXPRESSION,
                f"profile {self._profile} has masked columns, and {exc}",
            )
        for use in lineage.uses:
            if not self.masks[use.column].allow_in_predicates:
                return self._refusal(use)
        ctx.lineage = lineage
        return None

    def _refusal(self, use: Use) -> Refusal:
        schema, table, column = use.column
        masked = f"column {column} of {schema}.{table} is masked for profile {self._profile}"
        if use.kind == "predicate":
            return Refusal(
                RefusalCode.MASKED_COLUMN_IN_PREDICATE,
                f"{masked}, so the query can't use it in {use.where}: filtering, joining, "
                "grouping or sorting on it would reveal what the mask hides. Select it on its "
                "own, or leave it out",
            )
        return Refusal(
            RefusalCode.MASKED_COLUMN_IN_EXPRESSION,
            f"{masked}, so it can't be part of an expression ({use.where}). Select it on its "
            f"own, or count it with COUNT({column})",
        )
