"""The test portal: the MCP HTTP app at /mcp, and a page at / that talks to it.

The page and the MCP endpoint share one origin, so the browser needs no CORS, and the MCP
app's Origin check (loopback only) applies to the page exactly as it would to any client.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Mount, Route

from sql_warden.server import create_http_app
from sql_warden.warden import Warden

PAGE = Path(__file__).with_name("index.html")


async def index(request: Request) -> HTMLResponse:
    # Read on every request, so edits to the page show up on reload.
    return HTMLResponse(PAGE.read_text(), headers={"Cache-Control": "no-store"})


def create_portal_app(warden: Warden) -> Starlette:
    mcp_app = create_http_app(warden)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        # A mounted app's lifespan doesn't run by itself; the MCP session manager needs it.
        async with mcp_app.router.lifespan_context(mcp_app):
            yield

    return Starlette(
        routes=[Route("/", index), Mount("/", app=mcp_app)],
        lifespan=lifespan,
    )
