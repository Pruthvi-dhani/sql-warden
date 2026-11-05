"""Launch the test portal: uv run python -m tests.portal [--dsn ...] [--port 8765]"""

import logging
import threading
import webbrowser
from pathlib import Path

import click
import uvicorn

from sql_warden.cli import CliState, build_warden, engine_options, settings
from tests.portal.app import create_portal_app


@click.command()
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    envvar="SQL_WARDEN_CONFIG",
    help="Policy file, as for sql-warden (env: SQL_WARDEN_CONFIG).",
)
@engine_options
@click.option("--port", type=click.IntRange(1, 65535), default=8765, show_default=True)
@click.option("--open/--no-open", "open_browser", default=True, help="Open the page in a browser.")
def main(
    config_path: Path | None,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    profile: str | None,
    port: int,
    open_browser: bool,
) -> None:
    """Serve the sql-warden test portal on http://127.0.0.1:PORT/ (loopback only)."""
    logging.getLogger("sqlglot").setLevel(logging.ERROR)  # as the CLI does
    warden = build_warden(settings(CliState(config_path), dsn, max_rows, timeout_ms), profile)
    url = f"http://127.0.0.1:{port}/"
    click.echo(
        f"sql-warden test portal on {url}, profile {warden.profile} (Ctrl+C stops it)", err=True
    )
    if open_browser:
        threading.Timer(0.5, webbrowser.open, (url,)).start()
    uvicorn.run(create_portal_app(warden), host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
