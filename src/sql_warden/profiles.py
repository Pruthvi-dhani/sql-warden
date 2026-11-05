"""The profile a server serves: who is asking, and so which database role and rules apply.

A server is tied to one profile when it starts, by whoever deploys it. Nothing an agent sends
can change it: the tools take SQL, never a profile.
"""

from dataclasses import dataclass

from sql_warden.config import IMPLICIT_PROFILE, WardenConfig


class ProfileError(Exception):
    """No usable profile: an unknown name, or none picked when several are defined."""


@dataclass(frozen=True)
class Profile:
    name: str
    dsn: str
    """Where this profile connects: its own dsn, or warehouse.dsn."""
    own_dsn: bool
    """True if the profile has its own dsn, so the database itself limits what it can read."""
    implicit: bool = False
    """True when warden.yaml defines no profiles and this is the implicit `all`."""


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
        return Profile(IMPLICIT_PROFILE, warehouse_dsn, own_dsn=False, implicit=True)

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
    return Profile(name, profile.dsn or warehouse_dsn, own_dsn=profile.dsn is not None)
