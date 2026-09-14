"""Engine selection -- the one place in the process that consults engine identity.

Strategy selection, made once at startup. Everything downstream holds an `Engine` and reads
its declarations, so this module is the boundary that cross-cutting rule 2 draws: if a
second site ever needs to know which engine is in use, the capability it wanted belongs on
the `Engine` protocol instead.

Both engines are unimplemented at this stage -- Postgres lands in Stage 4, Snowflake in
Stage 14 -- so `build_engine` currently raises for every name. That is the intended state,
and it fails loudly with the stage that will fix it rather than returning a stub whose
methods deny everything and look, from the outside, exactly like a working guardrail.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Final

from sql_warden.engines.base import Engine, EngineName

if TYPE_CHECKING:  # pragma: no cover - import-time cycle: config imports engines.base
    from sql_warden.config import Config


class EngineNotImplemented(NotImplementedError):
    """The configured engine is a known name with no implementation yet.

    Distinct from an unknown name, which `EngineName` already rejects during config
    validation. This one means the config is legitimate and the code has not caught up.
    """


#: Which engine each name builds. Populated as engines land.
#:
#: A factory takes the whole `Config` because an engine needs more than its own name to
#: construct -- the target DSN, the statement timeout, the row cap -- and threading those
#: individually would mean changing this signature every time an engine wants one more.
EngineFactory = Callable[["Config"], Engine]

_FACTORIES: Final[Mapping[EngineName, EngineFactory]] = {
    # EngineName.POSTGRES: PostgresEngine.from_config,    # Stage 4
    # EngineName.SNOWFLAKE: SnowflakeEngine.from_config,  # Stage 14
}

#: Which stage implements each engine, so the error tells an operator when to expect it.
_ARRIVES_IN: Final[Mapping[EngineName, str]] = {
    EngineName.POSTGRES: "Stage 4",
    EngineName.SNOWFLAKE: "Stage 14",
}


def build_engine(config: Config) -> Engine:
    """Construct the engine named in config.

    Raises `EngineNotImplemented` if the name is valid but unbuilt. There is no fallback
    engine and there should not be one: silently substituting a different database than the
    one configured is the kind of helpfulness that ends with a policy written for Snowflake
    being enforced against Postgres.
    """
    name = config.server.engine
    factory = _FACTORIES.get(name)
    if factory is None:
        arrives = _ARRIVES_IN.get(name, "a later stage")
        raise EngineNotImplemented(
            f"engine {name.value!r} has no implementation yet; it arrives in {arrives}"
        )
    return factory(config)


def implemented_engines() -> frozenset[EngineName]:
    """Names that `build_engine` can actually build. Drives conformance parametrisation,
    so Stage 13's suite covers every engine that exists without listing them by hand.
    """
    return frozenset(_FACTORIES)
