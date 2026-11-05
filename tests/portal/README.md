# sql-warden test portal

A browser page for trying sql-warden by hand. It talks to the MCP server exactly as an agent
does (JSON-RPC over Streamable HTTP), so what you see is what an agent receives. It is a testing
tool: it lives in the tests tree and is not part of the `sql_warden` package.

```bash
docker compose -f dev/docker-compose.yml up -d     # the demo warehouse
uv run python -m tests.portal                      # opens http://127.0.0.1:8765/
```

Options are the same as `sql-warden`'s: `--config`, `--dsn`, `--max-rows`, `--timeout-ms`,
plus `--port` and `--no-open`. The portal only listens on 127.0.0.1.

## Panels

- **Query**: the SQL editor. **Run** calls `run_query`, **Check** calls `check_query` (a dry
  run). ⌘/Ctrl+Enter runs, ⇧⌘/Ctrl+Shift+Enter checks. **Examples** has a query for each kind
  of refusal.
- **Decision**: the verdict, then one line per check that ran (✓/✗, code, reason, time), any
  rewrites (such as an added LIMIT), and the SQL that ran or would run.
- **Results**: the rows, with NULLs marked and a note when the row cap cut the result off.
- **Tables**: from `list_tables`. Click a table to query it, a column to insert its name. The
  server re-reads the catalog at most once a minute, so a new table can take that long to show.
- **History**: the last 50 queries, kept in this browser's localStorage. Click one to load it.
- **Console**: every JSON-RPC request and response, newest first. Expand one to see the raw
  JSON.

`?sql=...` in the URL fills the editor, and `&tool=run` or `&tool=check` also submits it, so a
test query can be bookmarked:
`http://127.0.0.1:8765/?sql=select%20pg_sleep(1)&tool=check`.

## How it works

`__main__.py` builds the same `Warden` as the CLI and serves `app.py`: the MCP app from
`sql_warden.server.create_http_app` at `/mcp`, and `index.html` at `/`. Page and endpoint share
one origin, so no CORS is involved, and the MCP endpoint's loopback-only `Host`/`Origin` checks
apply to the page like any other client. The page is read on every request, so edits show up
on reload.

The page does `initialize`, then `notifications/initialized`, then `tools/call` with the
`Mcp-Session-Id` it was given. If the server forgets the session (a restart), the next call gets
a 404 and the page starts a new one. `test_portal.py` replays that sequence over real HTTP; the
JavaScript itself is kept thin and checked by hand.
