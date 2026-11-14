"""The warden.yaml policy file.

Unknown keys are errors, never ignored: a misspelt or not-yet-supported rule must not look
like it is being enforced. Each section is added together with the check that enforces it.
"""

import ipaddress
import os
import re
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

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
    SecretStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from sql_warden.engines.snowflake import DSN_FORM, SCHEME, SnowflakeDsn

# The read-only role in the dev/docker-compose.yml demo stack.
DEFAULT_DSN = "postgresql://warden_reader:warden_reader@localhost:5433/warehouse"
# The demo stack's audit database, a separate Postgres instance.
DEFAULT_AUDIT_DSN = "postgresql://warden_audit:warden_audit@localhost:5434/audit"

# Functions refused whatever the config says: they stall or signal the server, read its files,
# reach other databases, change session settings, take locks, write, or run SQL given as a
# string (which would slip past every check). Glob patterns, matched against lowercase names.
_POSTGRES_DENIED_FUNCTIONS = (
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
# Snowflake's: they stall or cancel sessions and change the account (SYSTEM$...), read what
# earlier queries returned, which no check or mask ever saw (RESULT_SCAN), show how objects
# are defined or who ran what, or reach files in stages.
_SNOWFLAKE_DENIED_FUNCTIONS = (
    "system$*",
    "result_scan",
    "last_query_id",
    "last_transaction",
    "get_ddl",
    "query_history*",
    "login_history*",
    "policy_references",
    "policy_context",
    "get_presigned_url",
    "get_stage_location",
    "get_absolute_path",
    "get_relative_path",
    "build_stage_file_url",
    "build_scoped_file_url",
    "external_table_files*",
    "infer_schema",
)
BUILTIN_DENIED_FUNCTIONS = {
    "postgres": _POSTGRES_DENIED_FUNCTIONS,
    "snowflake": _SNOWFLAKE_DENIED_FUNCTIONS,
}
"""Per SQL dialect: the checks read a query as its warehouse will."""
DIALECTS = tuple(BUILTIN_DENIED_FUNCTIONS)
BUILTIN_DENIED_TYPES = (
    "regclass",
    "regcollation",
    "regconfig",
    "regdictionary",
    "regnamespace",
    "regoper",
    "regoperator",
    "regproc",
    "regprocedure",
    "regrole",
    "regtype",
)
"""Postgres types a cast to which looks a name up in the catalog: `'t'::regclass` succeeds
only if there is a table t, whoever may read it. Never allowed, whatever the config says."""

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


def check_dsn(dsn: str, engine: str) -> None:
    """Raise PydanticCustomError unless dsn is one the engine can connect with. The message
    never repeats the DSN: it holds a password."""
    if engine != "snowflake":
        if dsn.startswith(f"{SCHEME}://"):
            raise PydanticCustomError(
                "dsn_engine",
                "is a Snowflake connection string, but warehouse.engine is {engine}",
                {"engine": engine},
            )
        return
    try:
        SnowflakeDsn.parse(dsn)
    except ValueError as exc:
        raise PydanticCustomError("dsn", "{problem}", {"problem": str(exc)}) from None


class WarehouseConfig(_Section):
    engine: Literal["postgres", "snowflake"] = "postgres"
    dsn: str = DEFAULT_DSN
    """How to connect. Postgres: a libpq connection string or URL. Snowflake:
    snowflake://USER:PASSWORD@ACCOUNT/DATABASE/SCHEMA?warehouse=WAREHOUSE&role=ROLE."""
    statement_timeout_ms: PositiveInt = 5_000
    """Snowflake counts in whole seconds, so there it is rounded up to the next one."""
    max_rows: PositiveInt = 100
    connect_timeout_s: PositiveInt = 5

    @model_validator(mode="after")
    def _dsn_fits_the_engine(self) -> Self:
        if self.engine == "snowflake" and "dsn" not in self.model_fields_set:
            raise PydanticCustomError(
                "dsn_missing", "the snowflake engine needs a dsn: {form}", {"form": DSN_FORM}
            )
        check_dsn(self.dsn, self.engine)
        return self

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
    allowed_types: tuple[str, ...] = ()
    """Types sqlglot does not know as standard SQL, which a query may cast to anyway: an
    enum, a domain, an extension's type, written as queries write them."""

    @field_validator("allowed_functions", "denied_functions", "allowed_types")
    @classmethod
    def _lowercase(cls, names: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(name.lower() for name in names)

    @field_validator("allowed_types")
    @classmethod
    def _no_type_is_always_denied(cls, names: tuple[str, ...]) -> tuple[str, ...]:
        for name in names:
            if name.rpartition(".")[2] in BUILTIN_DENIED_TYPES:
                raise PydanticCustomError(
                    "type_denied",
                    "allowed_types lists {name}, but a cast to it is never allowed",
                    {"name": name},
                )
        return names

    @model_validator(mode="after")
    def _nothing_allowed_is_denied(self) -> Self:
        for name in self.allowed_functions:
            # Against every dialect's list: no config can allow what one of them never does.
            pattern = next(filter(None, (self.denied_by(name, d) for d in DIALECTS)), None)
            if pattern is not None:
                raise PydanticCustomError(
                    "function_denied",
                    "allowed_functions lists {name}, but it is denied by '{pattern}'",
                    {"name": name, "pattern": pattern},
                )
        return self

    def denied_by(self, function: str, dialect: str = "postgres") -> str | None:
        """The denylist pattern that matches function in that dialect, or None if it is not
        denied."""
        name = function.lower()
        patterns = (*BUILTIN_DENIED_FUNCTIONS[dialect], *self.denied_functions)
        return next((pattern for pattern in patterns if fnmatchcase(name, pattern)), None)


SNOWFLAKE_MAX_TOTAL_COST = 10 * 1024**3
"""cost.max_total_cost when the engine is Snowflake and the file doesn't set it: 10 GiB."""


class CostConfig(_Section):
    """Limits on what a query may cost, from the database planner's estimate (EXPLAIN): a
    query estimated above them is refused before it runs."""

    max_total_cost: PositiveFloat = 1_000_000
    """In the planner's units. Postgres: reading one page in sequence costs 1; a full scan of
    a 1M-row table costs about 20,000, a cross join of two about 10^10. Snowflake: bytes the
    query may scan, and the default there is 10 GiB."""


class BudgetConfig(_Section):
    """What one session may use in total, across all its queries. A limit left out is not
    enforced."""

    max_queries: PositiveInt | None = None
    """Queries that were allowed and sent to the database."""
    max_total_cost: PositiveFloat | None = None
    """The sum of their estimated costs, in the planner's units (see CostConfig)."""
    max_rows_returned: PositiveInt | None = None
    """Rows returned, over all of them."""
    max_refusals: PositiveInt | None = None
    """Refused requests, dry runs included: stops a caller from trying query after query
    until one gets through."""

    @property
    def limited(self) -> bool:
        """True if any limit is set."""
        return any(limit is not None for limit in self.model_dump().values())


MAX_WINDOW_HOURS = 24 * 31


class IdentityBudgetConfig(BudgetConfig):
    """What one caller may use over a rolling window, across all their sessions: a token's
    holder can't start a fresh budget by connecting again. Only for callers with a token, so
    only with an auth section. A limit left out is not enforced."""

    window_hours: float = Field(default=24.0, gt=0, le=MAX_WINDOW_HOURS)
    """How far back their use counts: 24 is "in any 24 hours"."""

    @property
    def limited(self) -> bool:
        return any(
            getattr(self, limit) is not None
            for limit in ("max_queries", "max_total_cost", "max_rows_returned", "max_refusals")
        )

    @property
    def window_s(self) -> float:
        return self.window_hours * 3600


def default_cost(dialect: str) -> CostConfig:
    """The cost limits when none are given, in that dialect's planner's units."""
    return (
        CostConfig(max_total_cost=SNOWFLAKE_MAX_TOTAL_COST)
        if dialect == "snowflake"
        else CostConfig()
    )


class MaskingConfig(_Section):
    key: SecretStr | None = None
    """The key for hmac masks, shared by every profile: a value gets one token whichever
    profile sees it. Needed only if a profile uses hmac. Keep it out of the file, as
    `key: ${WARDEN_MASK_KEY}`: whoever has it can check guesses against tokens. Never shown."""

    @field_validator("key")
    @classmethod
    def _long_enough(cls, key: SecretStr | None) -> SecretStr | None:
        if key is not None and len(key.get_secret_value().encode()) < MIN_MASK_KEY_BYTES:
            raise PydanticCustomError(
                "mask_key_too_short",
                "must be at least {length} bytes",
                {"length": MIN_MASK_KEY_BYTES},
            )
        return key


LOOPBACK_NAMES = ("localhost",)


def is_loopback(host: str) -> bool:
    """True if host is this machine only: localhost, 127.0.0.1 and the rest of 127/8, ::1."""
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


LOOPBACK_ONLY = (
    "without an auth section sql-warden only listens on loopback (127.0.0.1, ::1 or "
    "localhost): whoever could reach the port would get everything its profile may read"
)
"""Why HTTP is not served to other machines unless callers must authenticate."""
_HOST_NAME = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")


class ServerConfig(_Section):
    """Where `sql-warden serve --transport http` listens. The --host and --port flags win."""

    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    allowed_hosts: tuple[str, ...] = ()
    """The names clients reach the server by, as their requests' Host header says: needed
    to listen beyond loopback, e.g. [warden.example.com]. Requests for any other name are
    refused, which stops DNS rebinding."""
    allowed_origins: tuple[str, ...] = ()
    """Web pages that may call the server from a browser, e.g. [https://portal.example.com].
    Requests from any other page are refused; requests from outside a browser carry no
    Origin and are not affected."""

    @field_validator("allowed_hosts")
    @classmethod
    def _host_names(cls, names: tuple[str, ...]) -> tuple[str, ...]:
        for name in names:
            if not _HOST_NAME.fullmatch(name):
                raise PydanticCustomError(
                    "host_name",
                    "{name} is not a host name: give the name alone, e.g. warden.example.com, "
                    "without a scheme, port or path",
                    {"name": name},
                )
        return tuple(name.lower() for name in names)

    @field_validator("allowed_origins")
    @classmethod
    def _origins(cls, origins: tuple[str, ...]) -> tuple[str, ...]:
        for origin in origins:
            parts = urlsplit(origin)
            if parts.scheme not in ("http", "https") or not parts.hostname or parts.path:
                raise PydanticCustomError(
                    "origin",
                    "{origin} is not an origin: give a scheme and host, e.g. "
                    "https://portal.example.com",
                    {"origin": origin},
                )
        return tuple(origin.lower() for origin in origins)

    @property
    def local(self) -> bool:
        return is_loopback(self.host)


_KEY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
SIGNING_ALGORITHMS = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
)
"""The ones a token may be signed with: public-key signatures only. A shared-secret one
(HS256) would let whoever can check a token make one, and `none` signs nothing."""


class ApiKeyConfig(_Section):
    """A key a caller sends as `Authorization: Bearer <key>`. Only its hash is kept here:
    `sql-warden auth new-key` makes one and prints both."""

    name: str
    """Who holds the key, e.g. support-bot: the identity the audit log records."""
    profile: str
    sha256: str
    """The SHA-256 of the key, in hex. A key is 256 random bits, so a fast hash is enough:
    there is nothing to guess."""

    @field_validator("name")
    @classmethod
    def _name(cls, name: str) -> str:
        if not _KEY_NAME.fullmatch(name):
            raise PydanticCustomError(
                "key_name",
                "a key's name is up to 64 letters, digits, '.', '_', ':', '@' or '-', "
                "starting with a letter or digit",
            )
        if name.lower().startswith("oidc:"):
            # Taken: an OIDC caller is oidc:<subject>, and two callers must never share a name.
            raise PydanticCustomError(
                "key_name", "a key's name can't start with oidc:, which names OIDC callers"
            )
        return name

    @field_validator("sha256")
    @classmethod
    def _hex(cls, digest: str) -> str:
        digest = digest.lower()
        if not _SHA256.fullmatch(digest):
            raise PydanticCustomError(
                "sha256",
                "must be the key's SHA-256 as 64 hex digits, as `sql-warden auth new-key` "
                "prints it; never the key itself",
            )
        return digest


def _https_unless_local(url: str, what: str) -> str:
    parts = urlsplit(url)
    local = parts.hostname is not None and is_loopback(parts.hostname)
    if parts.scheme == "https" or (parts.scheme == "http" and local):
        return url
    raise PydanticCustomError(
        "https", "{what} must be an https:// URL (http:// only on this machine)", {"what": what}
    )


class OidcConfig(_Section):
    """Tokens from an OpenID Connect provider: JWTs, checked against its published keys."""

    issuer: str
    """Exactly as the tokens' `iss` claim has it."""
    audience: str
    """What the tokens' `aud` claim must contain: this server's name at the provider."""
    jwks_url: str
    """Where the provider publishes the keys it signs with."""
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    profile_claim: str = "sql_warden_profile"
    """The claim that names the caller's profile, unless group_profiles is set."""
    group_claim: str = "groups"
    group_profiles: dict[str, str] = Field(default_factory=dict)
    """Group → profile. With it, the caller's profile comes from the groups listed in
    group_claim instead; groups that give two different profiles are refused."""
    leeway_s: int = Field(default=30, ge=0, le=300)
    """How far apart this machine's clock and the provider's may be."""

    @field_validator("issuer", "jwks_url")
    @classmethod
    def _secure(cls, url: str, info: ValidationInfo) -> str:
        return _https_unless_local(url, str(info.field_name))

    @field_validator("algorithms")
    @classmethod
    def _public_key_only(cls, algorithms: tuple[str, ...]) -> tuple[str, ...]:
        if not algorithms:
            raise PydanticCustomError("no_algorithms", "list at least one")
        for algorithm in algorithms:
            if algorithm not in SIGNING_ALGORITHMS:
                raise PydanticCustomError(
                    "algorithm",
                    "{algorithm} is not allowed: only public-key signatures ({allowed})",
                    {"algorithm": algorithm, "allowed": ", ".join(SIGNING_ALGORITHMS)},
                )
        return algorithms


class AuthConfig(_Section):
    """Who may call the server over HTTP, and which profile each gets. With this section,
    every HTTP request must carry a token, and one server serves every profile: each request
    is checked against its token's. stdio is not affected: whoever starts the process has
    already chosen its profile."""

    api_keys: tuple[ApiKeyConfig, ...] = ()
    oidc: OidcConfig | None = None

    @model_validator(mode="after")
    def _some_way_in(self) -> Self:
        if not self.api_keys and self.oidc is None:
            raise PydanticCustomError(
                "no_auth", "give api_keys, oidc, or both: otherwise nobody could get in"
            )
        for kind, values in (
            ("name", [key.name for key in self.api_keys]),
            ("sha256", [key.sha256 for key in self.api_keys]),
        ):
            repeated = sorted({value for value in values if values.count(value) > 1})
            if repeated:
                what = "names" if kind == "name" else "hashes"
                raise PydanticCustomError(
                    "duplicate_key",
                    "api_keys repeat {what}: {repeated}; each key is one caller's",
                    {"what": what, "repeated": ", ".join(repeated[:3])},
                )
        return self


class AuditConfig(_Section):
    """Where every request is recorded. Always Postgres, whatever the warehouse engine, and on
    its own instance: the warehouse role must not be able to touch the audit log. There is no
    way to turn auditing off: sql-warden refuses requests it can't record."""

    dsn: str = DEFAULT_AUDIT_DSN
    connect_timeout_s: PositiveInt = 5


EVERYTHING: Literal["*"] = "*"
MIN_MASK_KEY_BYTES = 16
ColumnRule = Literal["*"] | tuple[str, ...]
"""Every column of a table, including ones added later, or just these."""


class MaskRule(_Section):
    """How a profile sees one sensitive column. In warden.yaml, a strategy's name alone
    (`hmac`), or a mapping when it takes settings (`{strategy: partial, keep_last: 4}`)."""

    strategy: Literal["redact", "partial", "hmac", "null"]
    keep_first: NonNegativeInt | None = None
    keep_last: NonNegativeInt | None = None
    """partial only: how many characters stay readable at each end. Alone, `partial` keeps
    the last 4."""
    text: str | None = None
    """redact only: what replaces the value, instead of [REDACTED]."""
    allow_in_predicates: bool = False
    """Let queries filter, join, group and sort on the column, and compute with it. Off by
    default, because each of those can reveal what the mask hides (`WHERE ssn LIKE '123%'`).
    Worth turning on for a column that is hidden but not secret, like an hmac'd email that
    reports group by. What is computed from the column still comes back redacted."""

    @model_validator(mode="before")
    @classmethod
    def _name_alone(cls, rule: object) -> object:
        if isinstance(rule, str):
            rule = {"strategy": rule}
        if not isinstance(rule, dict) or rule.get("strategy") != "partial":
            return rule
        if rule.get("keep_first") is None and rule.get("keep_last") is None:
            return {**rule, "keep_last": 4}  # `partial` alone keeps the last 4
        return rule

    @model_validator(mode="after")
    def _settings_fit_the_strategy(self) -> Self:
        kept = [n for n in ("keep_first", "keep_last") if getattr(self, n) is not None]
        if self.strategy != "partial" and kept:
            raise PydanticCustomError(
                "mask_setting",
                "{setting} is for the partial strategy, not {strategy}",
                {"setting": kept[0], "strategy": self.strategy},
            )
        if self.strategy != "redact" and self.text is not None:
            raise PydanticCustomError(
                "mask_setting",
                "text is for the redact strategy, not {strategy}",
                {"strategy": self.strategy},
            )
        if self.strategy == "partial" and not (self.keep_first or 0) + (self.keep_last or 0):
            raise PydanticCustomError(
                "mask_keeps_nothing",
                "a partial mask that keeps nothing is a redaction: use redact",
            )
        return self


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
    masks: dict[str, MaskRule] = Field(default_factory=dict)
    """schema.table.column → how the profile sees it. Exact names, as in `tables`."""
    budgets: BudgetConfig | None = None
    """What one of the profile's sessions may use; any limit it leaves out comes from the
    top-level budgets section, and one it sets to null is lifted."""
    identity_budgets: IdentityBudgetConfig | None = None
    """What one of the profile's callers may use over the window; filled in from the
    top-level identity_budgets section as budgets are."""

    @field_validator("masks")
    @classmethod
    def _mask_names(cls, masks: dict[str, MaskRule]) -> dict[str, MaskRule]:
        for name in masks:
            parts = name.split(".")
            if len(parts) != 3 or not all(parts):
                raise PydanticCustomError(
                    "mask_name",
                    "'{name}' must be schema.table.column, e.g. public.customers.ssn",
                    {"name": name},
                )
        return masks

    @model_validator(mode="after")
    def _masks_are_readable(self) -> Self:
        # A mask on something the profile can't read protects nothing: most likely a typo,
        # which would leave the column it meant in the clear.
        for name in self.masks:
            table, _, column = name.rpartition(".")
            if self.tables == EVERYTHING:
                continue
            assert isinstance(self.tables, dict)
            if table not in self.tables:
                raise PydanticCustomError(
                    "mask_unreadable",
                    "masks {name}, but the profile doesn't read {table}",
                    {"name": name, "table": table},
                )
            columns = self.tables[table]
            if columns != EVERYTHING and column not in columns:
                raise PydanticCustomError(
                    "mask_unreadable",
                    "masks {name}, but the profile doesn't read column {column} of {table}",
                    {"name": name, "column": column, "table": table},
                )
        return self

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
    budgets: BudgetConfig = BudgetConfig()
    """What one session may use. No limits unless set: a session can be as long-lived as the
    agent that opened it."""
    identity_budgets: IdentityBudgetConfig = IdentityBudgetConfig()
    """What one caller (a token's identity) may use over a rolling window, across their
    sessions. No limits unless set."""
    masking: MaskingConfig = MaskingConfig()
    audit: AuditConfig = AuditConfig()
    server: ServerConfig = ServerConfig()
    auth: AuthConfig | None = None
    """None: HTTP needs no token, and is served on loopback only."""
    profiles: dict[str, ProfileConfig] | None = None
    """None: no profiles are defined, and the one profile is the implicit `all`."""
    default_profile: str | None = None
    """The profile a server uses when none is picked with --profile or SQL_WARDEN_PROFILE."""

    @model_validator(mode="before")
    @classmethod
    def _cost_in_the_engines_units(cls, data: object) -> object:
        # The planner's units differ per engine, so the default limit does too.
        if not isinstance(data, dict):
            return data
        warehouse, cost = data.get("warehouse"), data.get("cost")
        snowflake = isinstance(warehouse, dict) and warehouse.get("engine") == "snowflake"
        if not snowflake or (isinstance(cost, dict) and "max_total_cost" in cost):
            return data
        if cost is not None and not isinstance(cost, dict):
            return data  # not a section at all: its own validation says so
        return {**data, "cost": {**(cost or {}), "max_total_cost": SNOWFLAKE_MAX_TOTAL_COST}}

    @model_validator(mode="after")
    def _identity_budgets_need_identities(self) -> Self:
        if self.auth is not None:
            return self
        where = ["identity_budgets"] if self.identity_budgets.limited else []
        where += [
            f"profiles.{name}.identity_budgets"
            for name, profile in (self.profiles or {}).items()
            if profile.identity_budgets is not None and profile.identity_budgets.limited
        ]
        if where:
            raise PydanticCustomError(
                "identity_budgets_without_auth",
                "{where} limits what each caller with a token may use, but there is no auth "
                "section, so no caller has one: it would never be enforced",
                {"where": " and ".join(where)},
            )
        return self

    @model_validator(mode="after")
    def _auth_gives_real_profiles(self) -> Self:
        auth = self.auth
        if auth is None:
            if not self.server.local:
                raise PydanticCustomError(
                    "not_loopback",
                    "server.host is {host}, which other machines can reach: {why}",
                    {"host": self.server.host, "why": LOOPBACK_ONLY},
                )
            if self.server.allowed_hosts or self.server.allowed_origins:
                raise PydanticCustomError(
                    "hosts_without_auth",
                    "server.allowed_hosts and allowed_origins let callers in from elsewhere, "
                    "so they come with an auth section",
                )
            return self
        if self.profiles is None:
            raise PydanticCustomError(
                "auth_without_profiles",
                "auth maps callers to profiles, but there is no profiles section: define the "
                "profiles callers get",
            )
        given = [(f"api key {key.name}", key.profile) for key in auth.api_keys]
        if auth.oidc is not None:
            given += [(f"oidc group {g}", p) for g, p in auth.oidc.group_profiles.items()]
        for who, profile in given:
            if profile not in self.profiles:
                raise PydanticCustomError(
                    "unknown_auth_profile",
                    "auth gives {who} the profile '{profile}', but the config defines {known}",
                    {"who": who, "profile": profile, "known": ", ".join(self.profiles)},
                )
        if not self.server.local and not self.server.allowed_hosts:
            raise PydanticCustomError(
                "no_allowed_hosts",
                "server.host is {host}: list in server.allowed_hosts the names clients reach "
                "it by, e.g. [warden.example.com]",
                {"host": self.server.host},
            )
        return self

    @model_validator(mode="after")
    def _profile_dsns_fit_the_engine(self) -> Self:
        for name, profile in (self.profiles or {}).items():
            if profile.dsn is None:
                continue
            try:
                check_dsn(profile.dsn, self.warehouse.engine)
            except PydanticCustomError as exc:
                raise PydanticCustomError(
                    "profile_dsn",
                    "profile {name}'s dsn {problem}",
                    {"name": name, "problem": exc.message()},
                ) from None
        return self

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

    @model_validator(mode="after")
    def _hmac_has_a_key(self) -> Self:
        if self.masking.key is not None:
            return self
        for profile_name, profile in (self.profiles or {}).items():
            for name, rule in profile.masks.items():
                if rule.strategy == "hmac":
                    raise PydanticCustomError(
                        "mask_key_missing",
                        "profile {profile} masks {name} with hmac, which needs masking.key "
                        "(set it from the environment: key: ${WARDEN_MASK_KEY})",
                        {"profile": profile_name, "name": name},
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
    if dsn.startswith(f"{SCHEME}://"):
        try:
            return SnowflakeDsn.parse(dsn).describe()
        except ValueError:
            return "(unparseable connection string)"
    try:
        parts = conninfo_to_dict(dsn)
    except psycopg.Error:
        return "(unparseable connection string)"
    host = parts.get("host", "localhost")
    port = f":{parts['port']}" if "port" in parts else ""
    user = f" as {parts['user']}" if "user" in parts else ""
    return f"{host}{port}/{parts.get('dbname', '')}{user}"
