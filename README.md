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

> **Status:** under construction. The parse and shape checks, read-only engine, CLI, MCP server, Claude Code hookup, browser test portal, and per-profile table and column access
> work today; every request is recorded in the audit database, readable with
> `sql-warden audit`; the database planner's cost estimate gates every query before it runs;
> and sensitive columns come back masked per profile, which completes Phase 5. Next: sessions
> and query budgets. See the [plan](docs/plan.md) for the roadmap.

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
uv run sql-warden check "select count(*) from orders a cross join orders b"  # ✗ cost  COST_TOO_HIGH ...
```

`check` runs the checks and executes nothing: the database only plans the query, for the cost
check. `query` runs the same checks and, if they all pass, executes the SQL. Every query runs
in a read-only transaction with a statement timeout and a row cap.

What runs is the query as sql-warden parsed and checked it, regenerated from that tree, not
the text that was sent. Comments are dropped, so nothing the parser skipped over can reach the
database. A database error points into that SQL. Postgres finds many while it plans a query,
which the cost check has it do first, so they come back as a refusal before anything runs:

```text
$ uv run sql-warden query "select nope from products"
✓ parse  0.2 ms
✓ shape  0.1 ms
✗ cost   PLAN_FAILED: the database rejected the query while planning it: column "nope" does not exist
  SELECT nope FROM products LIMIT 101
         ^
HINT: Perhaps you meant to reference the column "products.name".
→ refused by cost (profile all)
```

An error only found while running, such as a division by zero on some row, is reported as
the database gave it (`Error: division by zero`, exit 1).

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

#### The audit log

Every `check` and `query`, from the CLI or an agent, is recorded in the audit database before
anything comes back: allowed, refused, failed or timed out, with the SQL as sent and as run,
the profile, the client, the full trace, and how many rows came back. The result's `audit_id`
(in `--json` and the MCP results) is the record's id.

It fails closed. sql-warden won't start without its audit database. If the audit database
goes away later, allowed queries are refused with `AUDIT_UNAVAILABLE` before they reach the
warehouse; if a record can't be written after a query ran, its rows are withheld. Nothing is
answered without a record.

Read it back with `sql-warden audit`:

```text
$ uv run sql-warden audit tail -n 3
ID        TIME                 KIND   PROFILE   CLIENT            RESULT                       SQL
c622c15e  2026-11-06 22:35:32  query  admin     sql-warden-port…  1 row                        select count(*) from employee_salaries
cd02f965  2026-11-06 22:42:49  query  public    cli               1 row                        select id, name from products where id = 3
5019a2f1  2026-11-06 22:42:50  check  public    cli               refused TABLE_NOT_ALLOWED    select email from customers

$ uv run sql-warden audit show 5019a2f1
event    5019a2f1-...
profile  public
client   cli
kind     check (dry run, nothing was executed)
result   refused by access: TABLE_NOT_ALLOWED (31 ms)
...
```

```bash
uv run sql-warden audit tail -f                          # follow along as an agent works (Ctrl+C stops)
uv run sql-warden audit tail --profile public --decision refused -n 50
uv run sql-warden audit tail --json | jq -r .sql          # one JSON object per event
uv run sql-warden audit show 5019a2f1 --json             # an id, or its first few characters
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
- **access**: only the tables and columns the server's [profile](#profiles) allows, wherever
  the query uses them (selected, filtered, joined, grouped or sorted on, in subqueries and
  CTEs). With the example config's `public` profile:

  | Try                                                           | Refused with           |
  |---------------------------------------------------------------|------------------------|
  | `select count(*) from employee_salaries`, `... from nosuch`   | `TABLE_NOT_ALLOWED`    |
  | `select email from customers`, `select category from products`| `TABLE_NOT_ALLOWED`, `COLUMN_NOT_ALLOWED` |
  | `select id from products order by category`                   | `COLUMN_NOT_ALLOWED`   |
  | `select * from products`, `select row_to_json(p) from products p` | `STAR_NOT_ALLOWED` (lists the allowed columns) |
  | `select 1 from information_schema.tables`                     | `TABLE_NOT_ALLOWED`    |

  A table that doesn't exist gets the same answer as one the profile may not read, and so does
  a column, so a profile can't probe for names. Allowed queries run with each table pinned to
  its schema (`products` → `public.products`), so the database reads the table that was
  checked. Without profiles there is no access check (the implicit profile `all`).

  With `shape.limit: inject` (the default), a query without a LIMIT gets one, and a LIMIT above
  the row cap is lowered. The new LIMIT is the row cap plus one, so the result can still say
  it was truncated. With `limit: require`, such queries are refused (`LIMIT_REQUIRED`,
  `LIMIT_TOO_HIGH`). `check` shows the rewrite and the SQL that would run:

  ```text
  $ uv run sql-warden check "select id from orders"
  ✓ parse  0.3 ms
  ✓ shape  0.1 ms
  ✓ cost   1.4 ms
  → allowed (profile all; dry run, nothing was executed)
    cost: 1.85 of 1,000,000 allowed (most of it: Seq Scan on orders)
    note: added LIMIT 101 (row cap 100 + 1 to detect truncation)
    would run: SELECT id FROM orders LIMIT 101
  ```
- **masking**: for a profile with [masked columns](#masked-columns), a masked column may
  only be selected as it is (then its values come back masked) or counted. Anything else could
  reveal what the mask hides, and is refused:

  | Try (as the example's `support` profile)                      | Refused with                  |
  |---------------------------------------------------------------|-------------------------------|
  | `select id from customers where ssn like '123%'`              | `MASKED_COLUMN_IN_PREDICATE`  |
  | `... join ... on c.email = ...`, `group by email`, `order by phone`, `distinct ssn` | `MASKED_COLUMN_IN_PREDICATE` |
  | `select upper(email)`, `split_part(email, '@', 2)`, `max(ssn)` | `MASKED_COLUMN_IN_EXPRESSION` |
  | `select count(distinct ssn) from customers`                   | allowed                       |

  The column is followed through aliases, CTEs, subqueries and unions, so renaming it changes
  nothing.
- **cost**: the database planner's estimate for the SQL that would run, from `EXPLAIN`, which
  plans a query without running it (never `EXPLAIN ANALYZE`). A query estimated above
  `cost.max_total_cost` (1,000,000 by default; a profile can set its own) is refused before it
  runs, and the reason names the step that costs the most. The estimate is in the response
  (`cost`) and the audit record. On the demo data:

  | Try                                                           | Estimate        | Result                  |
  |---------------------------------------------------------------|-----------------|-------------------------|
  | `select * from orders where id = 42`                          | about 8         | allowed                 |
  | `select sum(quantity) from orders` (a full scan)              | about 15,000    | allowed                 |
  | `select count(*) from orders a cross join orders b`           | about 10^10     | `COST_TOO_HIGH` (Nested Loop) |
  | `select 1 / 0`                                                | none: Postgres fails it while planning | `PLAN_FAILED` |

  A LIMIT is priced in: `select * from orders a cross join orders b` with the added
  `LIMIT 101` stops after 101 rows, and the planner knows it (cost about 2). If the database
  can't be reached to plan the query, it's refused with `COST_UNAVAILABLE`: a query whose cost
  is unknown doesn't run.

### MCP server

```bash
uv run sql-warden serve                      # stdio: for an agent that launches sql-warden itself
uv run sql-warden serve --transport http     # Streamable HTTP at http://127.0.0.1:8000/mcp
```

| Tool             | What it does                                                                  |
|------------------|-------------------------------------------------------------------------------|
| `run_query`      | checks the SQL and, if allowed, runs it and returns the rows                  |
| `check_query`    | dry run: the decision and the exact SQL that would run, nothing executed      |
| `list_tables`    | the tables and columns the profile may query, with types; cached for a minute |
| `describe_table` | one table's columns and types, and whether `SELECT *` works on it             |

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
`run_query`, `check_query`, `list_tables` and `describe_table` (`claude mcp list` checks it
from the shell).
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
docker compose -f dev/docker-compose.yml up -d              # the demo warehouse, if it isn't running
uv run python -m tests.portal                               # opens http://127.0.0.1:8765/
uv run python -m tests.portal --config warden.example.yaml  # with the public and admin profiles
```

With profiles, a picker in the header switches between them, and **Compare** shows what every
profile would decide about the query, side by side.

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

1. command-line flags (`--dsn`, `--max-rows`, `--timeout-ms`, `--profile`, `--audit-dsn`) and
   `SQL_WARDEN_DSN`, `SQL_WARDEN_PROFILE`, `SQL_WARDEN_AUDIT_DSN`
2. the file given by `--config PATH` or `SQL_WARDEN_CONFIG`
3. `./warden.yaml`, if it exists
4. built-in defaults for the local demo stack

Values can reference environment variables as `${NAME}` or `${NAME:-default}`, so passwords can
stay out of the file. Unknown keys are errors: a section appears in the file once sql-warden
enforces it. Today that is `warehouse` (connection, timeout, row cap), `audit` (the audit
database), `shape` (joins, nesting, LIMIT policy, function allow and deny lists), `cost`
(`max_total_cost`), `masking` (the hmac key) and `profiles`;
[warden.example.yaml](warden.example.yaml) documents every key.

### Profiles

A profile is who a server serves: say `public` for an agent released to customers, and `admin`
for internal admins. Each server is tied to one profile when it starts, and nothing an agent
sends can change it (the tools take only SQL):

```yaml
default_profile: public
profiles:
  public:      # an agent released to customers
    dsn: postgresql://warden_public:${WARDEN_PUBLIC_PASSWORD:-warden_public}@localhost:5433/warehouse
    tables:
      public.products: [id, name, price_cents]
    max_rows: 50                 # its own row cap
    cost:
      max_total_cost: 10000      # and a tighter cost limit
  admin:       # internal admins: connects with warehouse.dsn
    tables: "*"
    max_rows: 1000
```

```bash
cp warden.example.yaml warden.yaml                                                   # ships these two profiles
uv run sql-warden query "select count(*) from employee_salaries"                    # public: TABLE_NOT_ALLOWED
uv run sql-warden query "select count(*) from employee_salaries" --profile admin    # admin: 50
uv run sql-warden serve --profile public                                             # an MCP server for customers
```

`tables` is what a profile may query: `"*"` for every table its role can read, or
`schema.table` → `"*"` (every column, including ones added later) or a list of columns. A
profile that lists no tables can read nothing. `SELECT *` (and a whole-row reference like
`row_to_json(p)`) needs `"*"` for the table, since it would read columns the list leaves out.

The profile comes from `--profile`, else `SQL_WARDEN_PROFILE`, else `default_profile`. An
unknown name is an error, never a fallback. A profile's own `dsn` wins over `--dsn` and
`SQL_WARDEN_DSN`, so a flag can't widen what it reads. Its own `max_rows` wins over
`--max-rows` in the same way. Its `cost` limits replace the top-level ones it names, and the
rest come from the `cost` section. Every decision names its profile: the CLI prints it, and
`--json` and the MCP results carry `profile`.

### Masked columns

A profile can see a column it may read only masked. Masks are listed under the profile, so
`admin` can see in the clear what `support` sees masked:

```yaml
masking:
  key: ${WARDEN_MASK_KEY}      # for hmac; never in the file itself
profiles:
  support:
    tables:
      public.customers: "*"
    masks:
      public.customers.ssn: redact     # [REDACTED]
      public.customers.phone: partial  # ********0001: the last 4 kept
      public.customers.email: hmac     # 3f9a1c0b7e2d4a61: a keyed token
```

| Strategy  | Shows                                  | Settings                                        |
|-----------|----------------------------------------|-------------------------------------------------|
| `redact`  | `[REDACTED]`                           | `{strategy: redact, text: "***"}`               |
| `partial` | the ends, the rest starred: `********0001` | `keep_first`, `keep_last` (alone: the last 4). Never more than half a value |
| `hmac`    | a 16-hex-character token, the same for the same value, so results can still be matched and counted | needs `masking.key` (16+ bytes), shared by every profile |
| `null`    | nothing, not even whether there was a value | |

NULL stays NULL under the first three. A column made from more than one masked column (a
`UNION ALL` of two, say) comes back hidden whole. Responses list `masked_columns`, the CLI
prints `masked: email (hmac)`, `list_tables` marks masked columns with `mask`, and the audit
record lists them too.

A masked column can be selected or counted, nothing more (see the **masking** check). For a
column that is hidden but not secret, `{strategy: hmac, allow_in_predicates: true}` lets
queries filter, join, group and sort on it; what is computed from it still comes back hidden.

The hmac key is a secret: whoever has it can check a guess against a token. sql-warden has no
built-in key and won't start if a profile uses `hmac` without one. The example config's
default after `:-` is for the local demo stack only.

`list_tables`, `describe_table` and `sql-warden tables` show only what the profile may query,
so an agent never learns that the other tables exist. Each table says `all_columns`: whether
`SELECT *` works on it.

```bash
uv run sql-warden tables                     # public.products  id, name, price_cents  (some columns)
uv run sql-warden tables products --json     # the same payload describe_table returns
```

Give a profile its own `dsn` as a role with matching grants, and Postgres enforces the same
rules underneath (the demo's `warden_public` can read only those three product columns). The
access check reads the catalog to resolve names, so with profiles even `check` connects to the
database (to read the catalog, never to run the query); if it can't, the query is refused with
`CATALOG_UNAVAILABLE`. Without a `profiles` section there is one implicit profile, `all`, with
no table rules, and `config validate` says so. The demo database's `warden_public` role was
added with profiles: if your demo stack is older, reseed it with
`docker compose -f dev/docker-compose.yml down -v && docker compose -f dev/docker-compose.yml up -d`.
