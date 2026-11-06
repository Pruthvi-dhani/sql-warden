import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
import uvicorn
from mcp.server.mcpserver.exceptions import ToolError

from sql_warden import __version__
from sql_warden.audit import AuditError, AuditEvent, AuditSink, PostgresAuditSink
from sql_warden.config import (
    EVERYTHING,
    IMPLICIT_PROFILE,
    ConfigError,
    ProfileConfig,
    WardenConfig,
    default_config,
    describe_dsn,
    load_config,
)
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.profiles import ProfileError, select_profile
from sql_warden.render import (
    format_decision,
    format_rewrites,
    format_table,
    format_table_detail,
    format_tables,
)
from sql_warden.server import (
    create_http_app,
    create_server,
    describe,
    describe_one_table,
    describe_tables,
)
from sql_warden.warden import Warden

DEFAULT_CONFIG_PATH = Path("warden.yaml")
EXIT_ERROR = 1
EXIT_REFUSED = 2
"""A check refused the query. Nothing else exits 2, so scripts can tell a refusal apart."""
CLIENT = "cli"
"""How CLI requests are labelled in the audit log."""


@dataclass(frozen=True)
class CliState:
    config_path: Path | None


def resolve_config(path: Path | None) -> tuple[WardenConfig, str]:
    """The config to use and where it came from: --config, ./warden.yaml, or the defaults."""
    if path is None and DEFAULT_CONFIG_PATH.is_file():
        path = DEFAULT_CONFIG_PATH
    if path is None:
        return default_config(), "built-in defaults"
    try:
        return load_config(path), str(path)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc


def engine_options[F: Callable[..., Any]](command: F) -> F:
    command = click.option(
        "--audit-dsn",
        envvar="SQL_WARDEN_AUDIT_DSN",
        help="Audit database connection string; overrides audit.dsn (env: SQL_WARDEN_AUDIT_DSN).",
    )(command)
    command = click.option(
        "--profile",
        envvar="SQL_WARDEN_PROFILE",
        help="Profile to serve, from warden.yaml's profiles (env: SQL_WARDEN_PROFILE). "
        "Default: default_profile.",
    )(command)
    command = click.option(
        "--timeout-ms",
        type=click.IntRange(min=1),
        help="Statement timeout; overrides warehouse.statement_timeout_ms.",
    )(command)
    command = click.option(
        "--max-rows", type=click.IntRange(min=1), help="Row cap; overrides warehouse.max_rows."
    )(command)
    command = click.option(
        "--dsn",
        envvar="SQL_WARDEN_DSN",
        help="Warehouse connection string; overrides warehouse.dsn, which profiles without "
        "their own dsn use (env: SQL_WARDEN_DSN).",
    )(command)
    return command


def settings(
    state: CliState,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    audit_dsn: str | None = None,
) -> WardenConfig:
    """The config file's settings with the command-line overrides applied."""
    config, _ = resolve_config(state.config_path)
    overrides = {"dsn": dsn, "max_rows": max_rows, "statement_timeout_ms": timeout_ms}
    warehouse = config.warehouse.model_copy(
        update={key: value for key, value in overrides.items() if value is not None}
    )
    audit = (
        config.audit if audit_dsn is None else config.audit.model_copy(update={"dsn": audit_dsn})
    )
    return config.model_copy(update={"warehouse": warehouse, "audit": audit})


def open_audit(config: WardenConfig) -> PostgresAuditSink:
    """The audit log, with its table set up. sql-warden doesn't start without one."""
    sink = PostgresAuditSink(config.audit.dsn, connect_timeout_s=config.audit.connect_timeout_s)
    try:
        sink.ensure_schema()
    except AuditError as exc:
        raise click.ClickException(
            f"audit database at {describe_dsn(config.audit.dsn)}: {exc}\n"
            "sql-warden records every request and won't run without its audit database."
        ) from exc
    return sink


def json_option[F: Callable[..., Any]](command: F) -> F:
    return click.option(
        "--json",
        "as_json",
        is_flag=True,
        help="Print the decision as one line of JSON: what the MCP tools return.",
    )(command)


def build_warden(
    config: WardenConfig, profile: str | None = None, *, audit: AuditSink | None = None
) -> Warden:
    """A Warden for one profile, recording to audit (by default, the configured audit database).

    A profile's own dsn wins over --dsn and SQL_WARDEN_DSN: it is part of the policy, often a
    role that can read less, and a flag must not widen it."""
    try:
        active = select_profile(config, profile)
    except ProfileError as exc:
        raise click.ClickException(str(exc)) from exc
    if audit is None:
        audit = open_audit(config)
    warehouse = config.warehouse
    engine = PostgresEngine(
        active.dsn,
        statement_timeout_ms=warehouse.statement_timeout_ms,
        max_rows=warehouse.max_rows,
        connect_timeout_s=warehouse.connect_timeout_s,
    )
    return Warden(
        engine,
        audit=audit,
        dialect=warehouse.dialect,
        shape=config.shape,
        profile=active.name,
        access=active.access,
    )


class _NotRecorded:
    """The audit sink for commands that run no queries. If one ever did, it would be refused:
    a query is never answered without a record."""

    def ping(self) -> None:
        raise AuditError("this command does not record queries")

    def record(self, event: AuditEvent) -> None:
        self.ping()


NOT_RECORDED = _NotRecorded()


class UsageError(click.UsageError):
    exit_code = EXIT_ERROR


class Cli(click.Group):
    """Usage errors exit 1 like any other error; Click would use 2, which means refused here."""

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: click.Context | None = None,
        **extra: Any,
    ) -> click.Context:
        try:
            return super().make_context(info_name, args, parent, **extra)
        except click.UsageError as exc:
            raise UsageError(exc.format_message(), exc.ctx) from exc

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except click.UsageError as exc:
            raise UsageError(exc.format_message(), exc.ctx) from exc


@click.group(cls=Cli)
@click.version_option(__version__, prog_name="sql-warden")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    envvar="SQL_WARDEN_CONFIG",
    help="Policy file (env: SQL_WARDEN_CONFIG). Default: ./warden.yaml if present, "
    "otherwise settings for the local demo stack.",
)
@click.pass_context
def cli(ctx: click.Context, config_path: Path | None) -> None:
    """A governed SQL gateway for AI agents."""
    # sqlglot warns when it falls back to an opaque Command (DO, EXPLAIN, ...). The shape
    # check refuses those with its own reason; the warning would only be noise.
    logging.getLogger("sqlglot").setLevel(logging.ERROR)
    ctx.obj = CliState(config_path)


@cli.command()
@click.argument("sql")
@engine_options
@json_option
@click.pass_obj
def check(
    state: CliState,
    sql: str,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    profile: str | None,
    audit_dsn: str | None,
    as_json: bool,
) -> None:
    """Dry run: show what each check decides about SQL, without executing it.

    Exits 0 if the query would be allowed, 2 if a check refuses it, 1 on any other error.
    """
    warden = build_warden(settings(state, dsn, max_rows, timeout_ms, audit_dsn), profile)
    decision = warden.check(sql, client=CLIENT)
    if as_json:
        click.echo(describe(decision).model_dump_json(exclude_none=True))
    else:
        click.echo(format_decision(decision, dry_run=True))
    if not decision.allowed:
        raise SystemExit(EXIT_REFUSED)


@cli.command()
@click.argument("sql")
@engine_options
@json_option
@click.pass_obj
def query(
    state: CliState,
    sql: str,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    profile: str | None,
    audit_dsn: str | None,
    as_json: bool,
) -> None:
    """Run SQL through the checks and, if allowed, against the warehouse.

    Exits 0 if it ran, 2 if a check refused it, 1 if the database failed or on any other error.
    """
    warden = build_warden(settings(state, dsn, max_rows, timeout_ms, audit_dsn), profile)
    outcome = warden.run(sql, client=CLIENT)
    if as_json:
        click.echo(describe(outcome.decision, outcome).model_dump_json(exclude_none=True))
    if outcome.error is not None:
        if as_json:
            raise SystemExit(EXIT_ERROR)
        raise click.ClickException(str(outcome.error)) from outcome.error
    if outcome.result is None:
        if not as_json:
            click.echo(format_decision(outcome.decision, dry_run=False))
        raise SystemExit(EXIT_REFUSED)
    if not as_json:
        click.echo(format_table(outcome.result, profile=warden.profile))
        for note in format_rewrites(outcome.decision):
            click.echo(note)


@cli.command("tables")
@click.argument("name", required=False)
@engine_options
@json_option
@click.pass_obj
def tables_command(
    state: CliState,
    name: str | None,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    profile: str | None,
    audit_dsn: str | None,
    as_json: bool,
) -> None:
    """List the tables the profile may query, or describe one: `tables products`."""
    # Listing tables runs no query and isn't recorded, so it doesn't need the audit database.
    warden = build_warden(settings(state, dsn, max_rows, timeout_ms), profile, audit=NOT_RECORDED)
    try:
        if name is None:
            listed = describe_tables(warden)
            click.echo(listed.model_dump_json(by_alias=True) if as_json else format_tables(listed))
        else:
            one = describe_one_table(warden, name)
            click.echo(one.model_dump_json(by_alias=True) if as_json else format_table_detail(one))
    except ToolError as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command()
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http"]),
    default="stdio",
    show_default=True,
    help="stdio for an agent that launches sql-warden; http for local tools like the portal.",
)
@click.option(
    "--host", default="127.0.0.1", show_default=True, help="HTTP only. Loopback addresses only."
)
@click.option("--port", type=click.IntRange(1, 65535), default=8000, show_default=True)
@engine_options
@click.pass_obj
def serve(
    state: CliState,
    transport: str,
    host: str,
    port: int,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    profile: str | None,
    audit_dsn: str | None,
) -> None:
    """Serve the MCP tools for one profile, recording every query in the audit database."""
    warden = build_warden(settings(state, dsn, max_rows, timeout_ms, audit_dsn), profile)
    if transport == "stdio":
        create_server(warden).run("stdio")
        return
    try:
        app = create_http_app(warden, host=host)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    url_host = f"[{host}]" if ":" in host else host
    click.echo(
        f"sql-warden MCP server on http://{url_host}:{port}/mcp, profile {warden.profile} "
        "(Ctrl+C stops it)",
        err=True,
    )
    uvicorn.run(app, host=host, port=port, log_level="warning")


@cli.group()
def config() -> None:
    """Inspect the policy file."""


@config.command()
@click.argument("path", type=click.Path(path_type=Path, dir_okay=False), required=False)
@click.pass_obj
def validate(state: CliState, path: Path | None) -> None:
    """Check a policy file (default: --config, then ./warden.yaml) without connecting."""
    path = path or state.config_path
    if path is None and not DEFAULT_CONFIG_PATH.is_file():
        raise click.ClickException(
            "no config file to validate: pass a path or --config, or create ./warden.yaml "
            "(start from warden.example.yaml)"
        )
    loaded, source = resolve_config(path)
    warehouse, shape = loaded.warehouse, loaded.shape
    click.echo(f"✓ {source} is valid")
    click.echo(f"  warehouse: {warehouse.engine} at {describe_dsn(warehouse.dsn)}")
    click.echo(
        f"             statement timeout {warehouse.statement_timeout_ms} ms, "
        f"max {warehouse.max_rows} rows"
    )
    click.echo(f"  audit:     postgres at {describe_dsn(loaded.audit.dsn)}")
    click.echo(
        f"  shape:     up to {shape.max_joins} joins, "
        f"subqueries up to {shape.max_subquery_depth} deep"
    )
    click.echo(
        "             LIMIT added or lowered to the row cap"
        if shape.limit == "inject"
        else "             LIMIT required, up to the row cap"
    )
    if shape.allowed_functions or shape.denied_functions:
        click.echo(
            f"             {len(shape.allowed_functions)} extra functions allowed, "
            f"{len(shape.denied_functions)} extra denied"
        )
    for line in describe_profiles(loaded):
        click.echo(line)


def describe_profile_tables(profile: ProfileConfig) -> list[str]:
    if profile.tables == EVERYTHING:
        return ["reads every table its role can"]
    assert isinstance(profile.tables, dict)
    if not profile.tables:
        return ["reads nothing: it lists no tables"]
    return [
        f"reads {name} ({'every column' if columns == EVERYTHING else ', '.join(columns)})"
        for name, columns in profile.tables.items()
    ]


def describe_profiles(config: WardenConfig) -> list[str]:
    if config.profiles is None:
        return [
            f"  profiles:  ! none defined: every server uses the implicit profile "
            f"'{IMPLICIT_PROFILE}',",
            "             which can read everything the warehouse role can",
        ]
    lines = []
    for index, (name, profile) in enumerate(config.profiles.items()):
        label = "  profiles:  " if index == 0 else "             "
        default = " (default)" if name == config.default_profile else ""
        where = (
            f"connects to {describe_dsn(profile.dsn)}"
            if profile.dsn is not None
            else "connects with warehouse.dsn"
        )
        lines.append(f"{label}{name}{default}: {where}")
        lines += [f"               {line}" for line in describe_profile_tables(profile)]
    if config.default_profile is None:
        lines.append("             no default_profile: servers must be given --profile")
    return lines
