"""Server configuration -- the schema for plan.md §5.

Everything here is validated at load time. A guardrail whose configuration is wrong in a
way nobody notices is worse than no guardrail, because it still looks like one, so this
module prefers loud startup failures over anything that could silently leave a control
disengaged.
"""

from __future__ import annotations

import os
import re
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Final, Self
from urllib.parse import urlsplit

import yaml
from pydantic import BeforeValidator, Field, ValidationError, model_validator

from sql_warden.engines.base import SUPPORTED_COST_UNITS, CostUnit, EngineName
from sql_warden.models import FrozenModel

_DURATION = re.compile(r"^(?P<value>\d+)(?P<unit>ms|s|m|h)$")
_DURATION_FACTORS: Final[dict[str, float]] = {
    "ms": 0.001,
    "s": 1.0,
    "m": 60.0,
    "h": 3600.0,
}

_ENV_REF = re.compile(r"^\$\{(?P<name>[A-Z_][A-Z0-9_]*)\}$")


class ConfigError(ValueError):
    """Raised when configuration is unusable. Always fatal -- never a warning."""


def _parse_duration(value: object) -> object:
    """Accept `30s`, `5m`, `500ms`, or a bare number of seconds."""
    if isinstance(value, timedelta):
        return value
    if isinstance(value, int | float):
        return timedelta(seconds=float(value))
    if not isinstance(value, str):
        return value

    match = _DURATION.match(value.strip())
    if match is None:
        raise ConfigError(
            f"invalid duration {value!r}; expected a number of seconds or a value "
            f"suffixed with ms, s, m, or h (for example '30s' or '5m')"
        )
    return timedelta(seconds=int(match["value"]) * _DURATION_FACTORS[match["unit"]])


Duration = Annotated[timedelta, BeforeValidator(_parse_duration)]


class ServerConfig(FrozenModel):
    engine: EngineName
    policy_file: Path


class TargetConfig(FrozenModel):
    """Connection to the database the agent queries.

    plan.md §5 does not include this section -- an omission, since the server cannot
    connect without it. Added here so that the audit/target separation in §4.9 can be
    checked at load time rather than assumed.
    """

    dsn: str


class AuditConfig(FrozenModel):
    dsn: str


class LimitsConfig(FrozenModel):
    max_rows: int = Field(gt=0)
    statement_timeout: Duration


#: Thresholds for one engine: a limit per unit, any one of which can reject a query.
#:
#: An engine may report several units, and they measure genuinely different things. On
#: Snowflake `EXPLAIN USING JSON` returns partitions and bytes in one call: bytes tells you
#: how much data the query touches, partitions tells you whether pruning worked at all. A
#: query can be modest in one and alarming in the other -- a poorly filtered scan over a
#: well-clustered table reads few bytes while defeating pruning entirely -- so gating on
#: both catches queries that either alone would wave through. Configuring both is free,
#: because the engine produces them from the same call.
CostGates = dict[CostUnit, Annotated[float, Field(gt=0)]]


class RateLimit(FrozenModel):
    per_fingerprint: int = Field(gt=0)
    window: Duration


class BudgetConfig(FrozenModel):
    max_queries_per_session: int = Field(gt=0)
    max_cost_per_session: float = Field(gt=0)
    rate_limit: RateLimit


class CatalogConfig(FrozenModel):
    cache_ttl: Duration


class Config(FrozenModel):
    """The whole server configuration."""

    server: ServerConfig
    target: TargetConfig
    audit: AuditConfig
    limits: LimitsConfig
    #: Thresholds are nested per engine because the units are not interchangeable. A
    #: single top-level `max_cost` would be a design error (plan.md §5).
    cost_gate: dict[EngineName, CostGates]
    budget: BudgetConfig
    catalog: CatalogConfig

    @property
    def active_cost_gates(self) -> CostGates:
        """Every threshold for the selected engine. A query exceeding any one is rejected."""
        return self.cost_gate[self.server.engine]

    @model_validator(mode="after")
    def _selected_engine_has_a_cost_gate(self) -> Self:
        if not self.cost_gate.get(self.server.engine):
            raise ConfigError(
                f"no cost_gate configured for engine {self.server.engine!r}; without one "
                f"the cost gate would never fire and expensive queries would run unchecked"
            )
        return self

    @model_validator(mode="after")
    def _cost_gate_units_are_reportable_by_their_engine(self) -> Self:
        for engine, gates in self.cost_gate.items():
            supported = SUPPORTED_COST_UNITS[engine]
            for unit in gates:
                if unit not in supported:
                    readable = ", ".join(sorted(u.value for u in supported))
                    raise ConfigError(
                        f"engine {engine!r} cannot report cost in {unit.value!r}; "
                        f"it reports {readable}. A threshold in a unit the engine never "
                        f"produces is a gate that never fires."
                    )
        return self

    @model_validator(mode="after")
    def _audit_is_not_the_database_being_queried(self) -> Self:
        """plan.md §4.9, enforced rather than trusted.

        If a policy bug or parser bypass ever reaches the target, the evidence of what
        happened must not sit inside the blast radius. A config that points both at the
        same database defeats the entire audit design, and does so invisibly.
        """
        if _same_database(self.target.dsn, self.audit.dsn):
            raise ConfigError(
                "audit.dsn and target.dsn point at the same database; the audit trail "
                "must live outside the blast radius of the database being queried"
            )
        return self

    @classmethod
    def from_yaml(cls, path: Path | str) -> Config:
        """Load, expand `${ENV_VAR}` references, and validate.

        Raises `ConfigError` for anything wrong with the configuration -- a missing file,
        an unset environment variable, a bad type, or a failed cross-field rule. Pydantic
        wraps validator exceptions in its own `ValidationError`, so without this a caller
        would have to catch two exception types depending on *which* check failed, and
        would print a stack trace where an operator needs one readable line.
        """
        text = Path(path).read_text()
        raw: object = yaml.safe_load(text)
        if not isinstance(raw, dict):
            raise ConfigError(f"{path}: expected a YAML mapping at the top level")
        try:
            return cls.model_validate(_expand_env(raw))
        except ValidationError as exc:
            raise ConfigError(f"{path} is invalid:\n{_format_errors(exc)}") from exc


def _format_errors(exc: ValidationError) -> str:
    """Render Pydantic's errors as one line per problem, keyed by where it is in the file.

    An operator fixing a config wants `limits.max_rows: input should be greater than 0`,
    not a traceback.
    """
    lines: list[str] = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "<root>"
        message = error["msg"].removeprefix("Value error, ")
        lines.append(f"  {location}: {message}")
    return "\n".join(lines)


def _expand_env(node: object) -> object:
    """Replace `${VAR}` strings with their environment values, anywhere in the tree.

    An unset variable is fatal. The alternative -- substituting an empty string -- would
    turn a missing audit DSN into a server that starts up and writes its audit trail
    nowhere.
    """
    if isinstance(node, dict):
        return {key: _expand_env(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_expand_env(item) for item in node]
    if isinstance(node, str):
        match = _ENV_REF.match(node.strip())
        if match is None:
            return node
        name = match["name"]
        value = os.environ.get(name)
        if value is None:
            raise ConfigError(f"environment variable {name} is referenced by config but not set")
        return value
    return node


def _same_database(left: str, right: str) -> bool:
    """Compare two DSNs by what they actually address, ignoring credentials.

    String equality is not enough: the same database reached with two different passwords
    is still one blast radius.
    """
    a, b = urlsplit(left), urlsplit(right)
    return (a.hostname, a.port, a.path) == (b.hostname, b.port, b.path)
