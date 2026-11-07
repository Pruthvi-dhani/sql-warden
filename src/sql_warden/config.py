"""The warden.yaml policy file.

Unknown keys are errors, never ignored: a misspelt or not-yet-supported rule must not look
like it is being enforced. Each section is added together with the check that enforces it.
"""

import os
import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal, Self

import psycopg
import yaml
from psycopg.conninfo import conninfo_to_dict
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    NonNegativeInt,
    PositiveFloat,
    PositiveInt,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

# The read-only role in the dev/docker-compose.yml demo stack.
DEFAULT_DSN = "postgresql://warden_reader:warden_reader@localhost:5433/warehouse"
# The demo stack's audit database, a separate Postgres instance.
DEFAULT_AUDIT_DSN = "postgresql://warden_audit:warden_audit@localhost:5434/audit"

# Functions refused whatever the config says: they stall or signal the server, read its files,
# reach other databases, change session settings, take locks, write, or run SQL given as a
# string (which would slip past every check). Glob patterns, matched against lowercase names.
BUILTIN_DENIED_FUNCTIONS = (
    "pg_sleep*",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_*",
    "pg_stat_file",
    "pg_file_*",
    "lo_*",
    "loread",
    "lowrite",
    "dblink*",
    "set_config",
    "current_setting",
    "pg_cancel_backend",
    "pg_terminate_backend",
    "pg_reload_conf",
    "pg_rotate_logfile",
    "pg_advisory_*",
    "pg_try_advisory_*",
    "pg_notify",
    "pg_stat_reset*",
    "pg_switch_wal",
    "pg_promote",
    "pg_create_*",
    "pg_drop_*",
    "pg_logical_*",
    "pg_replication_*",
    "nextval",
    "setval",
    "query_to_xml*",
    "cursor_to_xml*",
    "table_to_xml*",
    "schema_to_xml*",
    "database_to_xml*",
)

# ${VAR} or ${VAR:-default}, in any string value.
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

IMPLICIT_PROFILE = "all"
"""The one profile there is when warden.yaml defines none: every table the role can read."""
# Profile names end up in URLs and audit records, so they stay simple.
_PROFILE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,62}")


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


class ShapeConfig(_Section):
    max_joins: NonNegativeInt = 4
    max_subquery_depth: NonNegativeInt = 3
    limit: Literal["inject", "require"] = "inject"
    """inject: add a LIMIT if missing, lower one above the row cap. require: refuse instead."""
    allowed_functions: tuple[str, ...] = ()
    """Functions sqlglot does not know as standard SQL, allowed anyway."""
    denied_functions: tuple[str, ...] = ()
    """Glob patterns refused on top of BUILTIN_DENIED_FUNCTIONS."""

    @field_validator("allowed_functions", "denied_functions")
    @classmethod
    def _lowercase(cls, names: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(name.lower() for name in names)

    @model_validator(mode="after")
    def _nothing_allowed_is_denied(self) -> Self:
        for name in self.allowed_functions:
            pattern = self.denied_by(name)
            if pattern is not None:
                raise PydanticCustomError(
                    "function_denied",
                    "allowed_functions lists {name}, but it is denied by '{pattern}'",
                    {"name": name, "pattern": pattern},
                )
        return self

    def denied_by(self, function: str) -> str | None:
        """The denylist pattern that matches function, or None if it is not denied."""
        name = function.lower()
        patterns = (*BUILTIN_DENIED_FUNCTIONS, *self.denied_functions)
        return next((pattern for pattern in patterns if fnmatchcase(name, pattern)), None)


class CostConfig(_Section):
    """Limits on what a query may cost, from the database planner's estimate (EXPLAIN): a
    query estimated above them is refused before it runs."""

    max_total_cost: PositiveFloat = 1_000_000
    """In the planner's units (Postgres: reading one page in sequence costs 1). A full scan of
    a 1M-row table costs about 20,000; a cross join of two, about 10^10."""


class AuditConfig(_Section):
    """Where every request is recorded. Always Postgres, whatever the warehouse engine, and on
    its own instance: the warehouse role must not be able to touch the audit log. There is no
    way to turn auditing off: sql-warden refuses requests it can't record."""

    dsn: str = DEFAULT_AUDIT_DSN
    connect_timeout_s: PositiveInt = 5


EVERYTHING: Literal["*"] = "*"
ColumnRule = Literal["*"] | tuple[str, ...]
"""Every column of a table, including ones added later, or just these."""


class ProfileConfig(_Section):
    """Who a server serves, e.g. an agent released to customers, or internal admins."""

    dsn: str | None = None
    """A connection, usually as a role that can read only what this profile may see. Without
    one, the profile connects with warehouse.dsn."""
    tables: Literal["*"] | dict[str, ColumnRule] = Field(default_factory=dict)
    """What the profile may read: "*" for every table, or schema.table → "*" or columns.
    A profile that lists no tables can read nothing."""
    max_rows: PositiveInt | None = None
    """The profile's row cap, instead of warehouse.max_rows."""
    cost: CostConfig | None = None
    """The profile's cost limits; any it leaves out come from the top-level cost section."""

    @field_validator("tables", mode="before")
    @classmethod
    def _table_rules(cls, tables: object) -> object:
        # Checked before pydantic's own validation, whose messages for a union are unreadable.
        if tables == EVERYTHING:
            return tables
        if not isinstance(tables, dict):
            raise PydanticCustomError(
                "tables",
                'tables must be "*" or a mapping of schema.table to "*" or a list of columns',
            )
        for name, columns in tables.items():
            schema, _, table = str(name).partition(".")
            if not schema or not table or "." in table:
                raise PydanticCustomError(
                    "table_name",
                    "'{name}' must be schema.table, e.g. public.products",
                    {"name": name},
                )
            if columns == EVERYTHING:
                continue
            if not isinstance(columns, list) or not all(isinstance(c, str) for c in columns):
                raise PydanticCustomError(
                    "column_rule",
                    '{name} must be "*" or a list of column names',
                    {"name": name},
                )
            if not columns:
                raise PydanticCustomError(
                    "no_columns",
                    '{name} lists no columns; give some, use "*", or leave the table out',
                    {"name": name},
                )
            repeated = sorted({column for column in columns if columns.count(column) > 1})
            if repeated:
                raise PydanticCustomError(
                    "repeated_columns",
                    "{name} lists {columns} more than once",
                    {"name": name, "columns": ", ".join(repeated)},
                )
        return tables


class WardenConfig(_Section):
    version: Literal[1]
    warehouse: WarehouseConfig = WarehouseConfig()
    shape: ShapeConfig = ShapeConfig()
    cost: CostConfig = CostConfig()
    audit: AuditConfig = AuditConfig()
    profiles: dict[str, ProfileConfig] | None = None
    """None: no profiles are defined, and the one profile is the implicit `all`."""
    default_profile: str | None = None
    """The profile a server uses when none is picked with --profile or SQL_WARDEN_PROFILE."""

    @field_validator("profiles")
    @classmethod
    def _profile_names(
        cls, profiles: dict[str, ProfileConfig] | None
    ) -> dict[str, ProfileConfig] | None:
        if profiles is None:
            return None
        if not profiles:
            raise PydanticCustomError(
                "no_profiles", "define at least one profile, or leave the section out"
            )
        for name in profiles:
            if name == IMPLICIT_PROFILE:
                raise PydanticCustomError(
                    "reserved_profile",
                    "'{name}' is the implicit profile used when none are defined; pick "
                    "another name",
                    {"name": name},
                )
            if not _PROFILE_NAME.fullmatch(name):
                raise PydanticCustomError(
                    "profile_name",
                    "profile name '{name}' must be lowercase letters, digits, '-' or '_', "
                    "starting with a letter",
                    {"name": name},
                )
        return profiles

    @model_validator(mode="after")
    def _default_profile_exists(self) -> Self:
        default = self.default_profile
        if default is None:
            return self
        if self.profiles is None:
            raise PydanticCustomError(
                "default_without_profiles",
                "default_profile is '{name}', but there is no profiles section",
                {"name": default},
            )
        if default not in self.profiles:
            raise PydanticCustomError(
                "unknown_default_profile",
                "default_profile is '{name}', which is not one of the profiles ({known})",
                {"name": default, "known": ", ".join(self.profiles)},
            )
        return self


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
