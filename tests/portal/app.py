"""The test portal: an MCP HTTP app per profile, and a page at / that talks to them.

Each profile's server is at /p/<profile>/mcp; /mcp is the default profile's. The page and the
MCP endpoints share one origin, so the browser needs no CORS, and the MCP apps' Origin check
(loopback only) applies to the page exactly as it would to any client.
"""

from collections.abc import AsyncIterator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import BaseRoute, Mount, Route

from sql_warden.server import create_http_app
from sql_warden.warden import Warden

PAGE = Path(__file__).with_name("index.html")


async def index(request: Request) -> HTMLResponse:
    # Read on every request, so edits to the page show up on reload.
    return HTMLResponse(PAGE.read_text(), headers={"Cache-Control": "no-store"})


def create_portal_app(
    wardens: Mapping[str, Warden] | Warden, *, default: str | None = None
) -> Starlette:
    """A portal for each Warden, by profile name; default is the one the page starts on."""
    if isinstance(wardens, Warden):
        wardens = {wardens.profile: wardens}
    default = default or next(iter(wardens))
    mcp_apps = {name: create_http_app(warden) for name, warden in wardens.items()}

    async def profiles(request: Request) -> JSONResponse:
        return JSONResponse({"profiles": list(wardens), "default": default})

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        # A mounted app's lifespan doesn't run by itself; each MCP session manager needs it.
        async with AsyncExitStack() as stack:
            for mcp_app in mcp_apps.values():
                await stack.enter_async_context(mcp_app.router.lifespan_context(mcp_app))
            yield

    routes: list[BaseRoute] = [Route("/", index), Route("/profiles", profiles)]
    routes += [Mount(f"/p/{name}", app=mcp_app) for name, mcp_app in mcp_apps.items()]
    routes.append(Mount("/", app=mcp_apps[default]))
    return Starlette(routes=routes, lifespan=lifespan)
