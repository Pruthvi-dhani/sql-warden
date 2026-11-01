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

> **Status:** under construction. The parse and shape checks, read-only engine and CLI work today; the MCP server and a browser test portal are next. See the [plan](docs/plan.md) for the roadmap.

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
database.

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
