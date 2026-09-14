"""Conformance to the `Engine` seam, and the JSON shape the envelope depends on.

Most of this file is checked by mypy rather than by pytest. The `Engine` protocol has no
implementations yet -- Stage 4 builds the first -- so the thing worth asserting now is that
the protocol is *satisfiable* and that an incomplete engine is *rejected*, both statically.
Running the file additionally proves the stub is constructible, which catches the case where
a protocol typechecks but names something that cannot exist at runtime.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlglot import exp

from sql_warden.catalog import Catalog, catalog_of
from sql_warden.engines.base import (
    CostEstimate,
    CostUnit,
    Enforced,
    EnforcementModel,
    Engine,
    EngineName,
    Guard,
    ResultSet,
    Session,
)
from sql_warden.pipeline.decisions import Deny, DenyReason, Stage


class StubGuard:
    """Refuses nothing. Stage 5 writes the real ones."""

    @property
    def name(self) -> str:
        return "stub"

    def check(self, ast: exp.Expression) -> Deny | None:
        return None


class RefusingGuard:
    @property
    def name(self) -> str:
        return "refusing"

    def check(self, ast: exp.Expression) -> Deny | None:
        return Deny(
            reason=DenyReason.FORBIDDEN_FUNCTION,
            stage=Stage.SHAPE,
            detail="stub guard refuses everything",
        )


class StubSession:
    @property
    def engine_query_id(self) -> str | None:
        return "stub-1"

    async def estimate(self, ast: exp.Query) -> CostEstimate:
        return CostEstimate(unit=CostUnit.PLANNER_COST, value=1.0, is_pre_execution=True)

    async def fetch(self, ast: exp.Query) -> ResultSet:
        return ResultSet(columns=("id",), rows=((1,),))


class StubEngine:
    """A complete implementation of `Engine` that touches no database.

    Its only job is to make the protocol's satisfiability a compile-time fact. If a method
    is added to `Engine` without being added here, the assignment at the bottom of this file
    stops typechecking -- which is the failure we want, at the moment we want it.
    """

    @property
    def name(self) -> EngineName:
        return EngineName.POSTGRES

    @property
    def sqlglot_dialect(self) -> str:
        return "postgres"

    def guards(self) -> Sequence[Guard]:
        return (StubGuard(), RefusingGuard())

    def enforcement(self) -> EnforcementModel:
        return EnforcementModel(
            readonly=Enforced.NATIVE,
            masking=Enforced.SERVER,
            row_limit=Enforced.SERVER,
            timeout=Enforced.NATIVE,
        )

    def apply_row_limit(self, ast: exp.Query, limit: int) -> exp.Query:
        return ast.limit(limit)

    async def introspect(self) -> Catalog:
        return catalog_of("postgres", [])

    def readonly_session(self, timeout: timedelta) -> AbstractAsyncContextManager[Session]:
        @asynccontextmanager
        async def session() -> AsyncIterator[Session]:
            yield StubSession()

        return session()

    async def close(self) -> None:
        return None


class IncompleteEngine:
    """Missing `introspect`, `readonly_session`, `apply_row_limit` and `close`."""

    @property
    def name(self) -> EngineName:
        return EngineName.POSTGRES

    @property
    def sqlglot_dialect(self) -> str:
        return "postgres"

    def guards(self) -> Sequence[Guard]:
        return ()

    def enforcement(self) -> EnforcementModel:
        return EnforcementModel(
            readonly=Enforced.NONE,
            masking=Enforced.NONE,
            row_limit=Enforced.NONE,
            timeout=Enforced.NONE,
        )


# -- the static half ------------------------------------------------------------------

#: A complete engine satisfies the protocol. Typechecks or the build fails.
_complete: Engine = StubEngine()

#: An incomplete one does not -- and this is the assertion, not the ignore. `mypy --strict`
#: enables `warn_unused_ignores`, so if `IncompleteEngine` ever *did* satisfy `Engine`, this
#: suppression would become unnecessary and mypy would fail on it. The negative case is
#: therefore enforced rather than merely commented.
_incomplete: Engine = IncompleteEngine()  # type: ignore[assignment]

#: Guards and sessions likewise.
_guard: Guard = StubGuard()
_session: Session = StubSession()


# -- the runtime half -----------------------------------------------------------------


def test_the_stub_engine_is_constructible() -> None:
    """A protocol can typecheck against something that cannot actually be built."""
    engine = StubEngine()

    assert engine.name is EngineName.POSTGRES
    assert engine.sqlglot_dialect == "postgres"
    assert len(engine.guards()) == 2


async def test_a_session_estimates_and_fetches() -> None:
    engine = StubEngine()

    async with engine.readonly_session(timedelta(seconds=30)) as session:
        estimate = await session.estimate(exp.select("1"))
        rows = await session.fetch(exp.select("1"))

    assert estimate.unit is CostUnit.PLANNER_COST
    assert estimate.is_pre_execution
    assert rows.columns == ("id",)
    assert session.engine_query_id == "stub-1"


def test_a_guard_returns_a_typed_denial_not_a_bool() -> None:
    """A guard knows why it refused, and that reason has to survive into the audit row and
    the metrics label. A bool would throw it away at the point it is cheapest to keep.
    """
    refusal = RefusingGuard().check(exp.select("1"))

    assert refusal is not None
    assert refusal.reason is DenyReason.FORBIDDEN_FUNCTION
    assert refusal.stage is Stage.SHAPE
    assert StubGuard().check(exp.select("1")) is None


def test_row_limit_is_an_ast_rewrite() -> None:
    """Not string concatenation. Stage 7 asks for `n + 1` rows so truncation is known
    rather than guessed, which only works if the limit is applied structurally.
    """
    limited = StubEngine().apply_row_limit(exp.select("id").from_("t"), 501)

    assert "LIMIT 501" in limited.sql(dialect="postgres")


# -- the envelope contract ------------------------------------------------------------


def test_enforcement_serialises_as_plain_strings() -> None:
    """plan.md §4.7 embeds this object in the result envelope and plan.md §4.9 writes it to
    an audit `jsonb` column. Both need bare strings; a `StrEnum` that leaked its repr would
    produce `"Enforced.NATIVE"` in the agent's envelope and in the evidence.
    """
    enforcement = EnforcementModel(
        readonly=Enforced.NATIVE,
        masking=Enforced.NATIVE,
        row_limit=Enforced.SERVER,
        timeout=Enforced.NATIVE,
    )

    dumped = enforcement.model_dump(mode="json")

    assert dumped == {
        "readonly": "native",
        "masking": "native",
        "row_limit": "server",
        "timeout": "native",
    }
    assert json.loads(enforcement.model_dump_json()) == dumped


def test_enforcement_covers_the_envelope_example() -> None:
    """The §4.7 example shows `{"masking": "native", "readonly": "native"}`. It is an
    abbreviated illustration, so this asserts it is a *subset* of what we emit rather than
    equal to it -- pinning the two fields the plan commits to by name.
    """
    dumped = EnforcementModel(
        readonly=Enforced.NATIVE,
        masking=Enforced.NATIVE,
        row_limit=Enforced.SERVER,
        timeout=Enforced.NATIVE,
    ).model_dump(mode="json")

    assert {"masking": "native", "readonly": "native"}.items() <= dumped.items()


def test_every_control_must_be_declared() -> None:
    """`extra="forbid"` plus required fields: an engine cannot omit a control and leave a
    reviewer to infer that it is enforced. plan.md's `Enforced.NONE` exists so a gap is
    stated rather than implied by omission.
    """
    with pytest.raises(ValidationError):
        EnforcementModel(readonly=Enforced.NATIVE)  # type: ignore[call-arg]


def test_cost_estimate_serialises_for_the_envelope() -> None:
    """§4.7 carries `"cost": {"unit": ..., "value": ...}`, and the unit travels with the
    number everywhere -- including out to the client.
    """
    dumped = CostEstimate(
        unit=CostUnit.BYTES_SCANNED,
        value=1_240_000_000,
        is_pre_execution=True,
        context="warehouse=WH_XSMALL",
    ).model_dump(mode="json")

    assert dumped["unit"] == "bytes_scanned"
    assert dumped["value"] == 1_240_000_000
    assert dumped["context"] == "warehouse=WH_XSMALL"
