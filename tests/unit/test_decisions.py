"""Tests for deny reasons and the disclosure split.

The security-relevant property here is one-directional: the audit log always gets the
full story, the client sometimes gets less. These tests pin both halves.
"""

from __future__ import annotations

import pytest

from sql_warden.pipeline.decisions import (
    COARSE_CODE,
    COARSE_MESSAGE,
    DISCLOSURE,
    Allow,
    Deny,
    DenyReason,
    Disclosure,
    Stage,
)

SECRET = "table analytics.kyc_documents is denied by policy rule #3"

COARSE_REASONS = [r for r in DenyReason if DISCLOSURE[r] is Disclosure.COARSE]
VERBATIM_REASONS = [r for r in DenyReason if DISCLOSURE[r] is Disclosure.VERBATIM]


@pytest.mark.parametrize("reason", list(DenyReason))
def test_every_reason_declares_a_disclosure_level(reason: DenyReason) -> None:
    """Parametrised over the enum, so a new `DenyReason` cannot be added without deciding
    what the agent is told. The default would otherwise be whatever the first call site
    happened to do.
    """
    assert reason in DISCLOSURE


def test_disclosure_map_has_no_entries_for_unknown_reasons() -> None:
    assert set(DISCLOSURE) == set(DenyReason)


@pytest.mark.parametrize("reason", COARSE_REASONS)
def test_coarse_rejections_never_leak_detail_to_the_client(reason: DenyReason) -> None:
    deny = Deny(reason=reason, stage=Stage.POLICY, detail=SECRET)

    client = deny.for_client()

    assert SECRET not in client.message
    assert reason.value not in client.code
    assert client.code == COARSE_CODE
    assert client.message == COARSE_MESSAGE


def test_all_coarse_rejections_are_indistinguishable_from_each_other() -> None:
    """The point of coarse disclosure, and the easiest thing to get wrong.

    If a denied table and a non-allowlisted schema produced even slightly different text,
    an agent could map the policy -- and confirm which objects exist on the server -- by
    diffing rejection messages. Distinct-but-vague is not coarse, it is an oracle with
    extra steps.
    """
    rendered = {
        Deny(reason=r, stage=Stage.POLICY, detail=f"detail for {r}").for_client()
        for r in COARSE_REASONS
    }

    assert len(rendered) == 1, f"coarse rejections differ from one another: {rendered}"


@pytest.mark.parametrize("reason", VERBATIM_REASONS)
def test_verbatim_rejections_carry_detail_so_the_agent_can_self_correct(
    reason: DenyReason,
) -> None:
    detail = "estimated planner cost 4,120,000 exceeds limit 250,000"
    deny = Deny(reason=reason, stage=Stage.COST, detail=detail)

    client = deny.for_client()

    assert client.message == detail
    assert client.code == reason.value


@pytest.mark.parametrize("reason", list(DenyReason))
def test_detail_is_always_preserved_for_the_audit_log(reason: DenyReason) -> None:
    """Redaction applies to the client only. A reviewer reading the audit database must
    see exactly why a query was refused, or the log is not evidence.
    """
    deny = Deny(reason=reason, stage=Stage.POLICY, detail=SECRET)

    assert deny.detail == SECRET


def test_policy_rejections_are_coarse_and_cost_rejections_are_verbatim() -> None:
    """plan.md §12's lean, pinned: coarse for policy, verbatim for shape and cost."""
    assert DISCLOSURE[DenyReason.TABLE_DENIED] is Disclosure.COARSE
    assert DISCLOSURE[DenyReason.SCHEMA_NOT_ALLOWED] is Disclosure.COARSE
    assert DISCLOSURE[DenyReason.COST_EXCEEDED] is Disclosure.VERBATIM
    assert DISCLOSURE[DenyReason.NOT_A_SELECT] is Disclosure.VERBATIM


def test_decisions_are_immutable() -> None:
    """A stage must not be able to downgrade another stage's rejection in place."""
    deny = Deny(reason=DenyReason.TABLE_DENIED, stage=Stage.POLICY, detail=SECRET)

    with pytest.raises(AttributeError):
        deny.reason = DenyReason.COST_EXCEEDED  # type: ignore[misc]  # frozen by design


def test_allow_carries_nothing() -> None:
    assert Allow() == Allow()


def test_stage_covers_the_pipeline_plus_budget() -> None:
    """The seven stages of plan.md §4.2, plus the budget checkpoint that runs at two of
    them. Budget is a real answer to "where was this rejected"; "parse" would not be.
    """
    assert {s.value for s in Stage} == {
        "parse",
        "budget",
        "shape",
        "resolve",
        "policy",
        "cost",
        "execute",
        "record",
    }
