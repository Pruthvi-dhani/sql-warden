import click

from sql_warden import __version__
from sql_warden.engines import EngineError
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.render import format_table

# The read-only role in the dev/docker-compose.yml demo stack.
DEFAULT_DSN = "postgresql://warden_reader:warden_reader@localhost:5433/warehouse"


@click.group()
@click.version_option(__version__, prog_name="sql-warden")
def cli() -> None:
    """A governed SQL gateway for AI agents."""


@cli.command()
@click.argument("sql")
@click.option(
    "--dsn",
    envvar="SQL_WARDEN_DSN",
    default=DEFAULT_DSN,
    show_default=True,
    help="Warehouse connection string (env: SQL_WARDEN_DSN).",
)
@click.option("--max-rows", type=click.IntRange(min=1), default=100, show_default=True)
@click.option("--timeout-ms", type=click.IntRange(min=1), default=5_000, show_default=True)
def query(sql: str, dsn: str, max_rows: int, timeout_ms: int) -> None:
    """Run SQL against the warehouse and print the result."""
    engine = PostgresEngine(dsn, statement_timeout_ms=timeout_ms, max_rows=max_rows)
    try:
        result = engine.execute(sql)
    except EngineError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(format_table(result))
