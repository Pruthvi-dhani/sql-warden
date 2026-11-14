"""The profile a server serves: who is asking, and so which database role and rules apply.

A server is tied to one profile when it starts, by whoever deploys it. Nothing an agent sends
can change it: the tools take SQL, never a profile.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

from sql_warden.config import (
    EVERYTHING,
    IMPLICIT_PROFILE,
    BudgetConfig,
    CostConfig,
    IdentityBudgetConfig,
    MaskRule,
    ProfileConfig,
    WardenConfig,
)

Columns = Literal["*"] | frozenset[str]
"""Every column of a table, including ones added later, or just these."""


class ProfileError(Exception):
    """No usable profile: an unknown name, or none picked when several are defined."""


@dataclass(frozen=True)
class Access:
    """What a profile may read. Names are exact, as the database stores them."""

    tables: Literal["*"] | Mapping[tuple[str, str], Columns]
    """Every table, or (schema, table) → its columns."""

    @classmethod
    def from_config(cls, profile: ProfileConfig) -> "Access":
        if profile.tables == EVERYTHING:
            return cls(EVERYTHING)
        assert isinstance(profile.tables, dict)
        rules: dict[tuple[str, str], Columns] = {}
        for name, columns in profile.tables.items():
            schema, _, table = name.partition(".")
            rules[(schema, table)] = EVERYTHING if columns == EVERYTHING else frozenset(columns)
        return cls(rules)

    def columns(self, schema: str, table: str) -> Columns | None:
        """The columns of schema.table this profile may read, or None if not the table."""
        if self.tables == EVERYTHING:
            return EVERYTHING
        assert not isinstance(self.tables, str)
        return self.tables.get((schema, table))


@dataclass(frozen=True)
class Profile:
    name: str
    dsn: str
    """Where this profile connects: its own dsn, or warehouse.dsn."""
    own_dsn: bool
    """True if the profile has its own dsn, so the database itself limits what it can read."""
    implicit: bool = False
    """True when warden.yaml defines no profiles and this is the implicit `all`."""
    access: Access | None = None
    """What the profile may read; None for the implicit `all`, which has no table rules."""
    max_rows: int | None = None
    """The profile's row cap; None to use warehouse.max_rows."""
    cost: CostConfig = field(default_factory=CostConfig)
    """The cost limits: the profile's own, filled in from the top-level cost section."""
    masks: Mapping[tuple[str, str, str], MaskRule] = field(default_factory=dict)
    """(schema, table, column) → how the profile sees it."""
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    """What one session may use: the profile's own limits, filled in from the top-level
    budgets section."""
    identity_budget: IdentityBudgetConfig = field(default_factory=IdentityBudgetConfig)
    """What one caller may use over the window, filled in the same way."""


def profile_cost(config: WardenConfig, profile: ProfileConfig) -> CostConfig:
    """The profile's cost limits: what it sets, and the top-level section's for the rest."""
    if profile.cost is None:
        return config.cost
    return config.cost.model_copy(update=profile.cost.model_dump(exclude_unset=True))


def profile_budget(config: WardenConfig, profile: ProfileConfig) -> BudgetConfig:
    """The profile's session budget: what it sets (null lifts a limit), and the top-level
    section's for the rest."""
    if profile.budgets is None:
        return config.budgets
    return config.budgets.model_copy(update=profile.budgets.model_dump(exclude_unset=True))


def profile_identity_budget(config: WardenConfig, profile: ProfileConfig) -> IdentityBudgetConfig:
    """The profile's per-caller budget: what it sets, and the top-level section's for the rest."""
    if profile.identity_budgets is None:
        return config.identity_budgets
    own = profile.identity_budgets.model_dump(exclude_unset=True)
    return config.identity_budgets.model_copy(update=own)


def select_profile(config: WardenConfig, name: str | None = None) -> Profile:
    """The profile called name, or default_profile if name is None. Never a fallback: an
    unknown name is an error, so a typo can't quietly serve the wrong profile."""
    warehouse_dsn = config.warehouse.dsn
    if config.profiles is None:
        if name not in (None, IMPLICIT_PROFILE):
            raise ProfileError(
                f"unknown profile '{name}': no profiles are configured, so the only one is "
                f"'{IMPLICIT_PROFILE}'"
            )
        return Profile(
            IMPLICIT_PROFILE,
            warehouse_dsn,
            own_dsn=False,
            implicit=True,
            cost=config.cost,
            budget=config.budgets,
            identity_budget=config.identity_budgets,
        )

    known = ", ".join(config.profiles)
    name = name or config.default_profile
    if name is None:
        raise ProfileError(
            f"no profile picked: pass --profile or set SQL_WARDEN_PROFILE to one of {known} "
            "(the config has no default_profile)"
        )
    profile = config.profiles.get(name)
    if profile is None:
        raise ProfileError(f"unknown profile '{name}': the config defines {known}")
    return Profile(
        name,
        profile.dsn or warehouse_dsn,
        own_dsn=profile.dsn is not None,
        access=Access.from_config(profile),
        max_rows=profile.max_rows,
        cost=profile_cost(config, profile),
        masks={_column(name): rule for name, rule in profile.masks.items()},
        budget=profile_budget(config, profile),
        identity_budget=profile_identity_budget(config, profile),
    )


def _column(name: str) -> tuple[str, str, str]:
    schema, table, column = name.split(".")
    return schema, table, column
