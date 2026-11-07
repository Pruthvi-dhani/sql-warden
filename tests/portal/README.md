# sql-warden test portal

A browser page for trying sql-warden by hand. It talks to the MCP server exactly as an agent
does (JSON-RPC over Streamable HTTP), so what you see is what an agent receives. It is a testing
tool: it lives in the tests tree and is not part of the `sql_warden` package.

```bash
docker compose -f dev/docker-compose.yml up -d     # the demo warehouse and audit database
uv run python -m tests.portal                      # opens http://127.0.0.1:8765/
```

Options are the same as `sql-warden`'s: `--config`, `--dsn`, `--max-rows`, `--timeout-ms`,
`--profile`, `--audit-dsn`, plus `--port` and `--no-open`. The portal only listens on
127.0.0.1. Like `sql-warden serve`, it records every Run and Check in the audit database and
won't start without it; each result's `audit_id` is in the console panel.

It serves every profile in the config at once. With no config file (no `--config`, no
`SQL_WARDEN_CONFIG` and no `./warden.yaml`) it serves the implicit profile `all` and, so there
is something to switch between, `warden.example.yaml`'s profiles too: `all`, `public` and
`admin`. With the example config:

```bash
uv run python -m tests.portal --config warden.example.yaml                  # starts on public
uv run python -m tests.portal --config warden.example.yaml --profile admin  # starts on admin
```

The **profile** picker in the header switches the page to another profile's server (a new
session; the choice is remembered), and **Compare** shows side by side what each profile would
decide about the query.

## Panels

- **Query**: the SQL editor. **Run** calls `run_query`, **Check** calls `check_query` (a dry
  run). ⌘/Ctrl+Enter runs, ⇧⌘/Ctrl+Shift+Enter checks. **Compare** calls `check_query` under
  every profile at once, so nothing runs N times.
- **Compare**: one row per profile: allowed (with the SQL that would run) or refused (with the
  check, code and reason). The profile the page is on is marked.
- **Decision**: the verdict, then one line per check that ran (✓/✗, code, reason, time), the
  planner's estimated cost against the profile's limit (with the costliest step), any rewrites
  (such as an added LIMIT), and the SQL that ran or would run.
- **Results**: the rows, with NULLs marked and a note when the row cap cut the result off.
- **Tables**: from `list_tables`, so only what the server's profile may query. Click a table to
  query it (`select *` where the profile may read every column, the allowed columns otherwise),
  a column to insert its name. Start the portal with `--profile` to see another profile. The
  server re-reads the catalog at most once a minute, so a new table can take that long to show.
- **History**: the last 50 queries, kept in this browser's localStorage. Click one to load it.
- **Console**: every JSON-RPC request and response, newest first. Expand one to see the raw
  JSON.

## Docs and examples

**docs & examples** in the header opens `/docs` in a tab of its own. Its example links and
"back to the portal" load into the portal's tab rather than opening more. It covers:
- **The API**: MCP only (no REST); which transport each client uses (this portal: Streamable
  HTTP, local only; Claude Code: stdio; the CLI: none, in-process); the session handshake; and
  the CLI command for each tool.
- **Tools**: read live with `tools/list` from the profile you pick, with the instructions the
  server gives an agent when it connects.
- **Responses**: the fields `run_query` and `check_query` return.
- **Refusal codes**: each one, with the check that raises it.
- **Examples**: a query for each kind of decision, each with its profile and what sql-warden
  does with it. **Open** loads one into the portal's editor; **Check**, **Run** and **Compare**
  also submit it.

The examples live in `examples.json`. Each names a profile from `warden.example.yaml` and its
expected outcome: `allowed`, `failed`, or a refusal code.
`tests/integration/test_portal_on_postgres.py` checks every one against the seeded warehouse,
so an example can't quietly stop doing what it says.

`?sql=...` in the URL fills the editor, and `&tool=run`, `&tool=check` or `&tool=compare` also
submits it; `&profile=admin` picks the profile. So a test query can be bookmarked:
`http://127.0.0.1:8765/?sql=select%20pg_sleep(1)&tool=check`.

## How it works

`__main__.py` builds the same `Warden` as the CLI for every profile, each with its own
connection and catalog, and serves `app.py`: one MCP app from
`sql_warden.server.create_http_app` per profile at `/p/<profile>/mcp`, the starting profile's
also at `/mcp`, the profile list at `/profiles`, `index.html` at `/`, `docs.html` at `/docs`
and `examples.json` at `/examples.json`. Page and endpoints
share one origin, so no CORS is involved, and the MCP endpoints' loopback-only
`Host`/`Origin` checks apply to the page like any other client. A session belongs to one
profile's server: another profile's endpoint doesn't know it. The pages and examples are
read on every request, so edits show up on reload.

The page does `initialize`, then `notifications/initialized`, then `tools/call` with the
`Mcp-Session-Id` it was given. If the server forgets the session (a restart), the next call gets
a 404 and the page starts a new one. `test_portal.py` replays that sequence over real HTTP; the
JavaScript itself is kept thin and checked by hand.
