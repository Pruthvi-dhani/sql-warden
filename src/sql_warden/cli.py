from collections.abc import Callable
from typing import Any

import click

from sql_warden import __version__
from sql_warden.engines import EngineError
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.render import format_decision, format_table
from sql_warden.warden import Warden

# The read-only role in the dev/docker-compose.yml demo stack.
DEFAULT_DSN = "postgresql://warden_reader:warden_reader@localhost:5433/warehouse"


def engine_options[F: Callable[..., Any]](command: F) -> F:
    command = click.option(
        "--timeout-ms", type=click.IntRange(min=1), default=5_000, show_default=True
    )(command)
    command = click.option(
        "--max-rows", type=click.IntRange(min=1), default=100, show_default=True
    )(command)
    command = click.option(
        "--dsn",
        envvar="SQL_WARDEN_DSN",
        default=DEFAULT_DSN,
        show_default=True,
        help="Warehouse connection string (env: SQL_WARDEN_DSN).",
    )(command)
    return command


def build_warden(dsn: str, max_rows: int, timeout_ms: int) -> Warden:
    return Warden(PostgresEngine(dsn, statement_timeout_ms=timeout_ms, max_rows=max_rows))


@click.group()
@click.version_option(__version__, prog_name="sql-warden")
def cli() -> None:
    """A governed SQL gateway for AI agents."""


@cli.command()
@click.argument("sql")
@engine_options
def check(sql: str, dsn: str, max_rows: int, timeout_ms: int) -> None:
    """Dry run: show what each check decides about SQL, without executing it."""
    decision = build_warden(dsn, max_rows, timeout_ms).check(sql)
    click.echo(format_decision(decision, dry_run=True))
    if not decision.allowed:
        raise SystemExit(1)


@cli.command()
@click.argument("sql")
@engine_options
def query(sql: str, dsn: str, max_rows: int, timeout_ms: int) -> None:
    """Run SQL through the checks and, if allowed, against the warehouse."""
    try:
        outcome = build_warden(dsn, max_rows, timeout_ms).run(sql)
    except EngineError as exc:
        raise click.ClickException(str(exc)) from exc
    if outcome.result is None:
        click.echo(format_decision(outcome.decision, dry_run=False))
        raise SystemExit(1)
    click.echo(format_table(outcome.result))
