"""The warden.yaml policy file.

Unknown keys are errors, never ignored: a misspelt or not-yet-supported rule must not look
like it is being enforced. Each section is added together with the check that enforces it.
"""

import os
import re
from pathlib import Path
from typing import Literal

import psycopg
import yaml
from psycopg.conninfo import conninfo_to_dict
from pydantic import BaseModel, ConfigDict, PositiveInt, ValidationError

# The read-only role in the dev/docker-compose.yml demo stack.
DEFAULT_DSN = "postgresql://warden_reader:warden_reader@localhost:5433/warehouse"

# ${VAR} or ${VAR:-default}, in any string value.
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(Exception):
    """The config file is missing or invalid. The message says where and why."""


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WarehouseConfig(_Section):
    engine: Literal["postgres"] = "postgres"
    dsn: str = DEFAULT_DSN
    statement_timeout_ms: PositiveInt = 5_000
    max_rows: PositiveInt = 100
    connect_timeout_s: PositiveInt = 5

    @property
    def dialect(self) -> str:
        return self.engine


class WardenConfig(_Section):
    version: Literal[1]
    warehouse: WarehouseConfig = WarehouseConfig()


def default_config() -> WardenConfig:
    """What sql-warden uses when there is no config file: the local demo stack."""
    return WardenConfig(version=1)


def load_config(path: Path) -> WardenConfig:
    try:
        text = path.read_text()
    except FileNotFoundError:
        raise ConfigError(f"{path}: file not found") from None
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read file: {exc.strerror}") from exc
    return parse_config(text, source=str(path))


def parse_config(text: str, *, source: str = "config") -> WardenConfig:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1}, col {mark.column + 1})" if mark else ""
        problem = getattr(exc, "problem", None) or str(exc)
        raise ConfigError(f"{source}: invalid YAML{where}: {problem}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{source}: the top level must be a mapping of sections")
    try:
        return WardenConfig.model_validate(_interpolate_env(raw, source))
    except ValidationError as exc:
        problems = "\n".join(f"  {_location(err['loc'])}: {err['msg']}" for err in exc.errors())
        raise ConfigError(f"{source}: invalid config\n{problems}") from exc


def _location(loc: tuple[int | str, ...]) -> str:
    return ".".join(str(part) for part in loc) or "(top level)"


def _interpolate_env(value: object, source: str) -> object:
    if isinstance(value, str):
        return _ENV_REF.sub(lambda m: _env_value(m, source), value)
    if isinstance(value, dict):
        return {key: _interpolate_env(item, source) for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(item, source) for item in value]
    return value


def _env_value(match: re.Match[str], source: str) -> str:
    name, default = match.group(1), match.group(2)
    value = os.environ.get(name)
    if value is not None:
        return value
    if default is not None:
        return default
    raise ConfigError(
        f"{source}: environment variable {name} is not set (referenced as {match[0]})"
    )


def describe_dsn(dsn: str) -> str:
    """A DSN for display: who connects where, never the password."""
    try:
        parts = conninfo_to_dict(dsn)
    except psycopg.Error:
        return "(unparseable connection string)"
    host = parts.get("host", "localhost")
    port = f":{parts['port']}" if "port" in parts else ""
    user = f" as {parts['user']}" if "user" in parts else ""
    return f"{host}{port}/{parts.get('dbname', '')}{user}"
