import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
import uvicorn

from sql_warden import __version__
from sql_warden.config import (
    ConfigError,
    WardenConfig,
    default_config,
    describe_dsn,
    load_config,
)
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.render import format_decision, format_rewrites, format_table
from sql_warden.server import create_http_app, create_server, describe
from sql_warden.warden import Warden

DEFAULT_CONFIG_PATH = Path("warden.yaml")
EXIT_ERROR = 1
EXIT_REFUSED = 2
"""A check refused the query. Nothing else exits 2, so scripts can tell a refusal apart."""


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
        help="Warehouse connection string; overrides warehouse.dsn (env: SQL_WARDEN_DSN).",
    )(command)
    return command


def settings(
    state: CliState, dsn: str | None, max_rows: int | None, timeout_ms: int | None
) -> WardenConfig:
    """The config file's settings with the command-line overrides applied."""
    config, _ = resolve_config(state.config_path)
    overrides = {"dsn": dsn, "max_rows": max_rows, "statement_timeout_ms": timeout_ms}
    warehouse = config.warehouse.model_copy(
        update={key: value for key, value in overrides.items() if value is not None}
    )
    return config.model_copy(update={"warehouse": warehouse})


def json_option[F: Callable[..., Any]](command: F) -> F:
    return click.option(
        "--json",
        "as_json",
        is_flag=True,
        help="Print the decision as one line of JSON: what the MCP tools return.",
    )(command)


def build_warden(config: WardenConfig) -> Warden:
    warehouse = config.warehouse
    engine = PostgresEngine(
        warehouse.dsn,
        statement_timeout_ms=warehouse.statement_timeout_ms,
        max_rows=warehouse.max_rows,
        connect_timeout_s=warehouse.connect_timeout_s,
    )
    return Warden(engine, dialect=warehouse.dialect, shape=config.shape)


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
    as_json: bool,
) -> None:
    """Dry run: show what each check decides about SQL, without executing it.

    Exits 0 if the query would be allowed, 2 if a check refuses it, 1 on any other error.
    """
    warden = build_warden(settings(state, dsn, max_rows, timeout_ms))
    decision = warden.check(sql)
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
    as_json: bool,
) -> None:
    """Run SQL through the checks and, if allowed, against the warehouse.

    Exits 0 if it ran, 2 if a check refused it, 1 if the database failed or on any other error.
    """
    warden = build_warden(settings(state, dsn, max_rows, timeout_ms))
    outcome = warden.run(sql)
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
        click.echo(format_table(outcome.result))
        for note in format_rewrites(outcome.decision):
            click.echo(note)


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
) -> None:
    """Serve the MCP tools: run_query, check_query and list_tables."""
    warden = build_warden(settings(state, dsn, max_rows, timeout_ms))
    if transport == "stdio":
        create_server(warden).run("stdio")
        return
    try:
        app = create_http_app(warden, host=host)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    url_host = f"[{host}]" if ":" in host else host
    click.echo(f"sql-warden MCP server on http://{url_host}:{port}/mcp (Ctrl+C stops it)", err=True)
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
