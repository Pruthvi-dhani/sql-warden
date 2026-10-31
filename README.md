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

Agents connect over MCP. Humans can use the `sql-warden` CLI.

> **Status:** under construction (Phase 0: scaffolding).

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
uv run sql-warden query "select pg_sleep(3)" --timeout-ms 500     # cancelled by the timeout
```

`check` runs the checks without touching the database. `query` runs the same checks and, if
they all pass, executes the SQL. Both connect to the demo warehouse as `warden_reader` by
default; point them elsewhere with `--dsn` or `SQL_WARDEN_DSN`. Every query runs in a read-only
transaction with a statement timeout and a row cap. So far the only check is `parse`.
