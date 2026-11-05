# sql-warden

A governed SQL gateway that lets an AI agent query a real database safely. The rules are
enforced by the server, not trusted to the prompt.

Every query runs through a series of checks before it touches the database:

1. **Shape**: it must be a single read-only `SELECT` within the approved structural rules.
2. **Access**: it may touch only approved tables and columns.
3. **Cost**: the database's own planner estimates the cost, and anything too expensive is
   refused before it runs.
4. **Budget**: each session has a query budget.
5. **Masking**: sensitive columns come back masked.

Any check can refuse a query with a specific code and reason. Every request is recorded in
a separate audit database.

Agents connect over MCP. Humans can use the `sql-warden` CLI, or the browser
[test portal](#test-portal), which shows exactly what an agent gets back:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/portal-refused-dark.png">
  <img alt="The test portal refusing a query whose CTE deletes rows: parse passes, shape fails with NOT_READ_ONLY" src="docs/images/portal-refused-light.png">
</picture>

> **Status:** under construction. The parse and shape checks, read-only engine, CLI, MCP server, Claude Code hookup and a browser test portal work today, which completes Phase 1.
> Table and column access rules are next. See the [plan](docs/plan.md) for the roadmap.

## Development

Requires [uv](https://docs.astral.sh/uv/) and Docker.

```bash
uv sync                                   # create .venv with Python 3.12 + dev tools
uv run ruff check . && uv run ruff format --check .
uv run mypy                               # strict
uv run pytest                             # unit + integration tests
uv run pytest -m "not integration"        # skip tests that need Docker
```

### Demo stack

```bash
docker compose -f dev/docker-compose.yml up -d
```

| Service     | Port | Database    | Purpose                                         |
|-------------|------|-------------|-------------------------------------------------|
| `warehouse` | 5433 | `warehouse` | the data agents query, seeded on first start    |
| `audit`     | 5434 | `audit`     | sql-warden's audit log, on a separate instance  |

The warehouse is seeded from [dev/warehouse_seed.sql](dev/warehouse_seed.sql) with deterministic
demo data: `products` (200), `customers` (10k, with `email`, `phone` and `ssn`), `orders` (1M) and
`employee_salaries` (50, meant to stay off-limits). sql-warden connects as `warden_reader`, which
can only `SELECT`.

```bash
psql postgresql://warden_reader:warden_reader@localhost:5433/warehouse
```

Integration tests start their own throwaway containers from the same seed, so they don't need
this stack running.

### Try it

```bash
uv run sql-warden check "select id, name from products"          # dry run: one line per check
uv run sql-warden check "select (1"                              # ✗ parse  PARSE_ERROR: Expecting ) ...
uv run sql-warden query "select id, name, price_cents from products order by id" --max-rows 5
uv run sql-warden query "select count(*) from orders a cross join orders b" --timeout-ms 500
```

`check` runs the checks without touching the database. `query` runs the same checks and, if
they all pass, executes the SQL. Every query runs in a read-only transaction with a statement
timeout and a row cap.

What runs is the query as sql-warden parsed and checked it, regenerated from that tree, not
the text that was sent. Comments are dropped, so nothing the parser skipped over can reach the
database. A database error points into that SQL:

```text
$ uv run sql-warden query "select nope from products"
Error: column "nope" does not exist
  SELECT nope FROM products LIMIT 101
         ^
HINT: Perhaps you meant to reference the column "products.name".
```

#### In scripts

`check` and `query` exit with a status a script can act on:

| Exit | Meaning                                                                      |
|------|------------------------------------------------------------------------------|
| `0`  | allowed: `check` would run it, `query` ran it                                |
| `2`  | refused by a check (nothing else exits 2)                                    |
| `1`  | anything else: the database failed, it was unreachable, a bad config or flag |

`--json` prints one line of JSON instead of text, the same payload the MCP tools return (see
[MCP server](#mcp-server)), including the `error` when the database fails:

```bash
uv run sql-warden query "select count(*) as n from orders" --json | jq '.result.rows'
if ! uv run sql-warden check "$SQL" --json > decision.json; then jq -r .reason decision.json; fi
```

#### The checks so far

- **parse**: the SQL must parse (`PARSE_ERROR` otherwise, with line and column).
- **shape**: one read-only `SELECT` within the structural rules in `warden.yaml`:

  | Try                                                           | Refused with           |
  |---------------------------------------------------------------|------------------------|
  | `select 1; select 2`                                          | `MULTIPLE_STATEMENTS`  |
  | `delete from orders`, `drop table orders`, `do $$ ... $$`     | `NOT_A_SELECT`         |
  | `with x as (delete from orders returning *) select * from x`  | `NOT_READ_ONLY`        |
  | `select * into copy from customers`, `... for update`         | `NOT_READ_ONLY`        |
  | `select pg_sleep(60)`, `pg_read_file(...)`, `dblink(...)`     | `FUNCTION_NOT_ALLOWED` |
  | `select age(created_at) from customers` (unknown function)    | `FUNCTION_NOT_ALLOWED` |
  | more than `max_joins` joins, or `max_subquery_depth` nesting  | `TOO_MANY_JOINS`, `SUBQUERY_TOO_DEEP` |
  | `select 1 limit all`                                          | `INVALID_LIMIT`        |

  Functions sqlglot doesn't recognise as standard SQL are refused unless they are listed in
  `shape.allowed_functions`. Built-in dangerous ones (`pg_sleep*`, `pg_read_file`, `lo_*`,
  `dblink*`, `set_config`, `query_to_xml`, ...) are refused even if listed.

  With `shape.limit: inject` (the default), a query without a LIMIT gets one, and a LIMIT above
  the row cap is lowered. The new LIMIT is the row cap plus one, so the result can still say
  it was truncated. With `limit: require`, such queries are refused (`LIMIT_REQUIRED`,
  `LIMIT_TOO_HIGH`). `check` shows the rewrite and the SQL that would run:

  ```text
  $ uv run sql-warden check "select id from orders"
  ✓ parse  0.3 ms
  ✓ shape  0.1 ms
  → allowed (dry run, nothing was executed)
    note: added LIMIT 101 (row cap 100 + 1 to detect truncation)
    would run: SELECT id FROM orders LIMIT 101
  ```

### MCP server

```bash
uv run sql-warden serve                      # stdio: for an agent that launches sql-warden itself
uv run sql-warden serve --transport http     # Streamable HTTP at http://127.0.0.1:8000/mcp
```

| Tool          | What it does                                                                 |
|---------------|------------------------------------------------------------------------------|
| `run_query`   | checks the SQL and, if allowed, runs it and returns the rows                 |
| `check_query` | dry run: the decision and the exact SQL that would run, nothing executed     |
| `list_tables` | the tables and views the warehouse role can read, with column types          |

Results are structured, so an agent can tell why a query was refused and fix it:

```json
{"refused": true, "check": "shape", "code": "NOT_A_SELECT",
 "reason": "only SELECT queries are allowed, not DELETE",
 "trace": [{"check": "parse", "passed": true, ...}, {"check": "shape", "passed": false, ...}]}
```

An allowed query comes back with `sql` (what ran), `rewrites`, the `trace` and a `result`
(`columns`, `rows`, `row_count`, `truncated`). Exact numbers come back as strings and times as
ISO 8601. `run_query` flags refusals and database errors as tool errors; `check_query` treats a
refusal as an answer.

The HTTP transport has no authentication yet, so it only listens on loopback (`127.0.0.1`,
`::1`, `localhost`) and rejects requests whose `Host` or `Origin` isn't local, which stops web
pages from reaching it through your browser.

### Claude Code

Claude Code can use sql-warden as a tool. It starts `sql-warden serve` itself over stdio, so
there is no port and nothing to keep running; only the demo stack needs to be up. Pick one:

```bash
# Just for you, in this project (saved in ~/.claude.json). Run it from the repo root.
claude mcp add sql-warden -- uv run --quiet --directory "$PWD" sql-warden serve

# Or as a project file. .mcp.json is git-ignored; Claude Code asks you to approve it once.
cp .mcp.json.example .mcp.json
```

Start `claude` in the repo and run `/mcp`: sql-warden should be listed as connected, with
`run_query`, `check_query` and `list_tables` (`claude mcp list` checks it from the shell).
Then ask in plain language and watch which tools Claude calls and what comes back:

| Ask Claude                                              | What you should see                             |
|---------------------------------------------------------|-------------------------------------------------|
| "What are the five best-selling products?"              | `list_tables`, then a join over `orders`        |
| "How many customers signed up each month?"              | rows, and a note that a LIMIT was added         |
| "Run `delete from orders` through sql-warden"           | refused, `NOT_A_SELECT`, with the reason        |
| "Run `select pg_sleep(60)` through sql-warden"          | refused, `FUNCTION_NOT_ALLOWED`                 |
| "Count every pair of rows in orders with a cross join"  | passes the checks, cancelled at the timeout     |

The server reads `./warden.yaml` from the repo, like the CLI. To use another policy, set
`SQL_WARDEN_CONFIG` for it: `-e SQL_WARDEN_CONFIG=/path/to/warden.yaml` with `claude mcp add`,
or an `"env"` entry in `.mcp.json`. Keep passwords out of both: put them in `warden.yaml` as
`${VAR}` references. A policy change takes effect when the server restarts (reconnect it from
`/mcp`).

Until access rules arrive in Phase 2, Claude can read every table `warden_reader` can,
including `employee_salaries`.

### Test portal

A browser page for trying sql-warden by hand. It is a real MCP client of the same server agents
use, so a query it allows or refuses is allowed or refused for an agent too.

```bash
docker compose -f dev/docker-compose.yml up -d     # the demo warehouse, if it isn't running
uv run python -m tests.portal                      # opens http://127.0.0.1:8765/
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/portal-allowed-dark.png">
  <img alt="The test portal running a join: both checks pass, LIMIT 101 is added, and the rows are shown" src="docs/images/portal-allowed-light.png">
</picture>

For each query it shows:

- the verdict, and one line per check with its code, reason and time;
- any rewrites (such as an added LIMIT) and the exact SQL that ran or would run;
- the rows, with a note when the row cap cut them off;
- every JSON-RPC request and response, in the console.

The sidebar lists the tables the warehouse role can read (click one to query it) and your
history. **Examples** has a query for each kind of refusal, and `?sql=...&tool=run` in the URL
runs a query on load, so a test case can be bookmarked. The portal only listens on 127.0.0.1 and
takes the same options as `sql-warden` (`--config`, `--dsn`, `--max-rows`, `--timeout-ms`), plus
`--port` and `--no-open`. It is a testing tool, so it lives in `tests/` and is not part of the
package. More in [tests/portal/README.md](tests/portal/README.md).

## Configuration

sql-warden reads its policy from `warden.yaml`. Start from the example:

```bash
cp warden.example.yaml warden.yaml
uv run sql-warden config validate          # checks the file without connecting
```

Which config is used, highest priority first:

1. command-line flags (`--dsn`, `--max-rows`, `--timeout-ms`) and `SQL_WARDEN_DSN`
2. the file given by `--config PATH` or `SQL_WARDEN_CONFIG`
3. `./warden.yaml`, if it exists
4. built-in defaults for the local demo stack

Values can reference environment variables as `${NAME}` or `${NAME:-default}`, so passwords can
stay out of the file. Unknown keys are errors: a section appears in the file once sql-warden
enforces it. Today that is `warehouse` (connection, timeout, row cap) and `shape` (joins,
nesting, LIMIT policy, function allow and deny lists); [warden.example.yaml](warden.example.yaml)
documents every key.
