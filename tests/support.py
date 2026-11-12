"""Helpers shared by the unit, integration and portal tests."""

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import uvicorn
from starlette.types import ASGIApp

TOOLS = {"run_query", "check_query", "budget_status", "list_tables", "describe_table"}
"""Every tool the MCP server offers."""


@contextmanager
def serving(app: ASGIApp) -> Iterator[str]:
    """Serve app with uvicorn on a free loopback port in a background thread.

    Yields the base URL, e.g. http://127.0.0.1:54321.
    """
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert thread.is_alive(), "uvicorn exited before it started"
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
