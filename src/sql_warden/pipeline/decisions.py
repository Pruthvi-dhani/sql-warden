"""Decisions, deny reasons, and how much of a rejection the client is told.

Every stage of the admission pipeline returns `Allow` or `Deny`. `DenyReason` is a closed
enum because it drives three things at once: the audit log, the metrics labels, and the
message the agent sees so it can correct itself.

The disclosure split resolves plan.md §12's second open question. A rejection is useful
feedback -- an agent told "estimated cost 4.1M exceeds 250k" adds a WHERE clause and
succeeds -- but a rejection is also information, and policy structure is not the agent's
to learn. So `Deny` carries a full `detail` that is *always* audited, and exposes a
separate, possibly redacted view for the client.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class Stage(StrEnum):
    """Where a decision was made.

    The seven pipeline stages of plan.md §4.2, plus `BUDGET`. Budget is not a pipeline
    stage -- it is a checkpoint that runs at two moments (after PARSE for query count and
    fingerprint rate limiting, and inside COST for cumulative spend). It gets its own
    value regardless, because this enum answers "where was this rejected?" in the audit
    log, and answering "parse" for a rate-limited query would be untrue: parsing
    succeeded.
    """

    PARSE = "parse"
    BUDGET = "budget"
    SHAPE = "shape"
    RESOLVE = "resolve"
    POLICY = "policy"
    COST = "cost"
    EXECUTE = "execute"
    RECORD = "record"


class DenyReason(StrEnum):
    """Why a query was rejected. Closed by design -- see the module docstring."""

    # -- PARSE ------------------------------------------------------------------
    PARSE_ERROR = "parse_error"
    MULTIPLE_STATEMENTS = "multiple_statements"

    # -- BUDGET -----------------------------------------------------------------
    SESSION_QUERY_LIMIT = "session_query_limit"
    SESSION_COST_LIMIT = "session_cost_limit"
    RATE_LIMITED = "rate_limited"

    # -- SHAPE ------------------------------------------------------------------
    NOT_A_SELECT = "not_a_select"
    DISALLOWED_NODE = "disallowed_node"
    FORBIDDEN_FUNCTION = "forbidden_function"

    # -- RESOLVE ----------------------------------------------------------------
    UNKNOWN_OBJECT = "unknown_object"
    SCHEMA_NOT_ALLOWED = "schema_not_allowed"

    # -- POLICY -----------------------------------------------------------------
    TABLE_DENIED = "table_denied"

    # -- COST -------------------------------------------------------------------
    COST_EXCEEDED = "cost_exceeded"
    COST_UNAVAILABLE = "cost_unavailable"

    # -- EXECUTE ----------------------------------------------------------------
    EXECUTION_TIMEOUT = "execution_timeout"
    EXECUTION_ERROR = "execution_error"
    #: The engine role refused a query the parser admitted. Defence in depth firing is a
    #: parser bug, and one of the highest-signal events in the audit log.
    ENGINE_REFUSED = "engine_refused"

    # -- RECORD -----------------------------------------------------------------
    AUDIT_WRITE_FAILED = "audit_write_failed"


class Disclosure(StrEnum):
    """How much of a rejection the client is allowed to see."""

    #: Reason code and full detail. The agent can act on it.
    VERBATIM = "verbatim"

    #: A single generic code and message. The agent learns only that it was refused.
    COARSE = "coarse"


#: The code returned to the client for every coarse rejection.
COARSE_CODE: Final = "restricted"

#: The message returned to the client for every coarse rejection.
#:
#: Deliberately identical across *all* coarse reasons. If a denied table and a
#: non-allowlisted schema produced different text, the difference would itself be an
#: oracle -- an agent could map the policy, and confirm which objects exist on the server,
#: purely by diffing rejection messages. Coarse only works if coarse denials are
#: indistinguishable from one another.
COARSE_MESSAGE: Final = "The query was refused. The requested object is not available."


#: Disclosure level per reason.
#:
#: Shape, parse, cost and budget rejections are verbatim: they describe what the *query*
#: did wrong, they are actionable, and telling the agent cuts wasted turns and wasted
#: spend. Policy, schema and execution rejections are coarse: they describe what the
#: *server* is configured to protect, which is not the agent's to enumerate.
#:
#: `SCHEMA_NOT_ALLOWED` is coarse for a subtler reason than `TABLE_DENIED`. Distinguishing
#: "that schema is not allowlisted" from "no such object" confirms whether a schema exists
#: at all, which is a probe for what else lives on the server.
DISCLOSURE: Final[Mapping[DenyReason, Disclosure]] = {
    DenyReason.PARSE_ERROR: Disclosure.VERBATIM,
    DenyReason.MULTIPLE_STATEMENTS: Disclosure.VERBATIM,
    DenyReason.SESSION_QUERY_LIMIT: Disclosure.VERBATIM,
    DenyReason.SESSION_COST_LIMIT: Disclosure.VERBATIM,
    DenyReason.RATE_LIMITED: Disclosure.VERBATIM,
    DenyReason.NOT_A_SELECT: Disclosure.VERBATIM,
    DenyReason.DISALLOWED_NODE: Disclosure.VERBATIM,
    DenyReason.FORBIDDEN_FUNCTION: Disclosure.VERBATIM,
    DenyReason.UNKNOWN_OBJECT: Disclosure.VERBATIM,
    DenyReason.SCHEMA_NOT_ALLOWED: Disclosure.COARSE,
    DenyReason.TABLE_DENIED: Disclosure.COARSE,
    DenyReason.COST_EXCEEDED: Disclosure.VERBATIM,
    DenyReason.COST_UNAVAILABLE: Disclosure.COARSE,
    DenyReason.EXECUTION_TIMEOUT: Disclosure.VERBATIM,
    DenyReason.EXECUTION_ERROR: Disclosure.COARSE,
    DenyReason.ENGINE_REFUSED: Disclosure.COARSE,
    DenyReason.AUDIT_WRITE_FAILED: Disclosure.COARSE,
}


@dataclass(frozen=True, slots=True)
class ClientDeny:
    """The rejection as the agent sees it, after redaction."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class Allow:
    """The stage raised no objection. Carries nothing -- stages mutate the query through
    their own return values, not through the decision.
    """


@dataclass(frozen=True, slots=True)
class Deny:
    """The stage refused the query.

    `detail` is the full internal explanation and is *always* written to the audit log,
    regardless of disclosure. Only the client's view is ever redacted: a reviewer reading
    the audit database must see exactly why something was refused, or the log is not
    evidence.
    """

    reason: DenyReason
    stage: Stage
    detail: str

    @property
    def disclosure(self) -> Disclosure:
        return DISCLOSURE[self.reason]

    def for_client(self) -> ClientDeny:
        """Render this rejection for the agent, redacting if the reason is coarse."""
        if self.disclosure is Disclosure.VERBATIM:
            return ClientDeny(code=self.reason.value, message=self.detail)
        return ClientDeny(code=COARSE_CODE, message=COARSE_MESSAGE)


#: A stage's verdict. Union rather than a bool-plus-optional so that a `Deny` without a
#: reason is unrepresentable.
Decision = Allow | Deny
