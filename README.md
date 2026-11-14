# sql-warden

A governed SQL gateway that lets an AI agent query a real database safely. The rules are
enforced by the server, not trusted to the prompt.

Every query runs through a series of checks before it touches the database:

1. **Shape**: it must be a single read-only `SELECT` within the approved structural rules.
2. **Access**: it may touch only approved tables and columns.
3. **Cost**: the database's own planner estimates the cost, and anything too expensive is
   refused before it runs.
4. **Budget**: each session has a budget of queries, cost, rows and refusals.
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
> and sensitive columns come back masked per profile. Every request belongs to a session,
> and a session can have a budget: queries, total cost, rows and refusals. A session's usage
> is read back from the audit log, so its budget outlives the server that counted it. A
> server looks at its database role before it starts, and
> [doesn't serve as one that can write](#defence-in-depth). The warehouse can be Postgres or [Snowflake](#snowflake); the Snowflake engine is tested on an
> emulator and has not yet run against a real account. See the [plan](docs/plan.md) for the
> roadmap.

## Development

Requires [uv](https://docs.astral.sh/uv/) and Docker.

```bash
uv sync                                   # create .venv with Python 3.12 + dev tools
uv run ruff check . && uv run ruff format --check .
uv run mypy                               # strict
uv run pytest                             # unit + integration tests
uv run pytest -m "not integration"        # skip tests that need Docker
```

The Snowflake engine has two more sets of tests, each run on its own (see
[Snowflake](#snowflake)): `tests/fakesnow` on an emulator, and `tests/snowflake` against a
real account.

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
the profile, the client, the full trace, and how many rows came back. (Two things are not
kept exactly as sent: a query too long to be read is recorded as its first 2,000 characters
and its length, and characters Postgres can't store as text are written as escapes.) The result's `audit_id`
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
uv run sql-warden audit tail --session nightly-report    # everything one session asked
```

#### Sessions

Every request belongs to a session, and its record in the audit log says which
(`session_id`, also in `--json` and the MCP results). A session is one caller's run of
requests:

| Caller                         | Its session                                                     |
|--------------------------------|-----------------------------------------------------------------|
| an agent over stdio            | the server process: the agent starts it, and it serves only that agent |
| a client over HTTP that connects | its connection; reconnecting starts a new session              |
| a client over HTTP that doesn't, with a token | its caller's own session, while the server runs   |
| a client over HTTP that doesn't, no token     | the server's one session, shared with every other such client |
| `sql-warden query` and `check` | each call, unless calls are given the same `--session NAME`      |

```bash
uv run sql-warden query "select count(*) from orders" --session nightly-report
uv run sql-warden check "select * from customers"     --session nightly-report
uv run sql-warden audit tail --session nightly-report
```

A name is up to 64 letters, digits, `.`, `_`, `:` or `-`. Over HTTP the id is sql-warden's own,
derived from the transport's `Mcp-Session-Id` rather than being it: whoever holds that header's
value can use the connection, so it stays out of responses and the audit log.

Whether an HTTP client connects depends on the MCP version it speaks. Before 2026-07-28 a
client opens a connection with a handshake and sends its `Mcp-Session-Id` with every request.
From 2026-07-28 on there are no connections over HTTP: each request stands alone, and nothing
on it says which other requests came from the same caller, except its token. With
[authentication](#authentication) each caller has a session of their own, kept while the
server runs: the same caller is the same session from any client, and a restarted server
starts everyone afresh. Without it those requests are all one session, the server's own: a
limit then holds for the server as a whole, so it can't be got around, but one caller can use
it up for the others.

Sessions are what [budgets](#session-budgets) count against.

#### The checks so far

- **parse**: the SQL must parse (`PARSE_ERROR` otherwise, with line and column). Before
  that it must be safe to read at all. The parser goes back and tries again when it guessed
  wrong, and a query built for that (`date(date(date(...` thirty levels deep) would keep it
  busy for hours, so a query over 20,000 characters, with brackets nested more than 32 deep,
  or with more than 4 nested type names followed by a bracket (`date(`, `array[`) is turned
  away unread, as `QUERY_TOO_COMPLEX`.
- **shape**: one read-only `SELECT` within the structural rules in `warden.yaml`:

  | Try                                                           | Refused with           |
  |---------------------------------------------------------------|------------------------|
  | `select 1; select 2`                                          | `MULTIPLE_STATEMENTS`  |
  | `delete from orders`, `drop table orders`, `do $$ ... $$`     | `NOT_A_SELECT`         |
  | `with x as (delete from orders returning *) select * from x`  | `NOT_READ_ONLY`        |
  | `select * into copy from customers`, `... for update`         | `NOT_READ_ONLY`        |
  | `select pg_sleep(60)`, `pg_read_file(...)`, `dblink(...)`     | `FUNCTION_NOT_ALLOWED` |
  | `select age(created_at) from customers` (unknown function)    | `FUNCTION_NOT_ALLOWED` |
  | `select 'secrets'::regclass`, `select (null::secrets).*`      | `TYPE_NOT_ALLOWED`     |
  | more than `max_joins` joins, or `max_subquery_depth` nesting  | `TOO_MANY_JOINS`, `SUBQUERY_TOO_DEEP` |
  | `select 1 limit all`                                          | `INVALID_LIMIT`        |

  Functions sqlglot doesn't recognise as standard SQL are refused unless they are listed in
  `shape.allowed_functions`. Built-in dangerous ones (`pg_sleep*`, `pg_read_file`, `lo_*`,
  `dblink*`, `set_config`, `query_to_xml`, ...) are refused even if listed.

  Casts work the same way. In Postgres every table is also a type, and some types look a
  name up in the catalog, so `'secrets'::regclass` or `(null::secrets).*` would tell which
  tables exist and what their columns are called, whatever the profile may read. A cast to a
  type that isn't standard SQL is refused unless the type is listed in `shape.allowed_types`
  (an enum, a domain, an extension's type); `regclass`, `regrole` and the rest of that
  family are refused even if listed.

  The checks read a query in its warehouse's dialect, Postgres or Snowflake, and each has its
  own list of those functions (Snowflake's: `system$*`, `result_scan`, `get_ddl`,
  `query_history*`, ...). Read as Snowflake, a query must also name outright everything it
  reads, so these are refused too, even where no profile limits tables:

  | Try                                                   | Refused with           |
  |-------------------------------------------------------|------------------------|
  | `select * from identifier('secrets')`, `table('secrets')`, `table($t)` | `FUNCTION_NOT_ALLOWED` |
  | `select $1 from @my_stage/file.csv` (a stage's files)  | `TABLE_NOT_ALLOWED`    |
  | `select $3 from products` (a column by position), `$variable` | `COLUMN_NOT_ALLOWED` |
  | `select my_sequence.nextval`                           | `NOT_READ_ONLY`        |

  `select top 5000 ...` is a LIMIT like any other: it is lowered to the row cap.
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
- **budget**: for a profile with a [session budget](#session-budgets). A session that has
  reached a limit is refused before any other check looks at its query
  (`BUDGET_EXHAUSTED`); otherwise the budget comes last, once the cost is known, and refuses
  a query that costs more than the session has left (`COST_OVER_BUDGET`).
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
| `budget_status`  | what the session has used of its budget and what is left; free, never refused |

Results are structured, so an agent can tell why a query was refused and fix it:

```json
{"refused": true, "check": "shape", "code": "NOT_A_SELECT",
 "reason": "only SELECT queries are allowed, not DELETE",
 "trace": [{"check": "parse", "passed": true, ...}, {"check": "shape", "passed": false, ...}]}
```

An allowed query comes back with `sql` (what ran), `rewrites`, the `trace` and a `result`
(`columns`, `rows`, `row_count`, `truncated`). Every response names its `session_id` and
`audit_id`. Exact numbers come back as strings and times as
ISO 8601. `run_query` flags refusals and database errors as tool errors; `check_query` treats a
refusal as an answer.

Before it serves anything, `serve` asks the warehouse what its role can do, and doesn't start
as one that can write, or while the warehouse can't be asked: see
[Defence in depth](#defence-in-depth).

#### Over HTTP

Without an [`auth` section](#authentication) HTTP serves one profile, needs no token, and
only listens on loopback (`127.0.0.1`, `::1`, `localhost`). It rejects requests whose `Host`
or `Origin` isn't local, which stops web pages from reaching it through your browser. Where
it listens is `server.host` and `server.port` in `warden.yaml`, or `--host` and `--port`; an
address other machines can reach is refused by both, and by `config validate`.

It serves many clients at once. Each query runs in a worker thread with its own database
connection, so a slow one holds up nobody else's. What keeps one client from using the
server up:

| Limit                                 | Past it                                                    |
|---------------------------------------|------------------------------------------------------------|
| a request body of 256 KiB             | `413`, unread (a query is at most 20,000 characters)       |
| 10,000 open connections               | `503` for a new one until another closes                   |
| 30 minutes without a request          | the connection is closed; the client connects again, as a new [session](#sessions) |
| a made-up or expired `Mcp-Session-Id` | `404`: a client can't choose its session, or join another's |

The connection limits are for clients that connect; see [Sessions](#sessions) for the ones
that don't.

#### Authentication

With an `auth` section, every HTTP request must carry `Authorization: Bearer <token>`, and
one server serves every profile: the token says who the caller is and which profile their
queries are checked against. Nothing an agent sends can choose another. stdio is not
affected: whoever starts the process has already picked its profile, with `--profile`.

```yaml
auth:
  api_keys:                      # made with `sql-warden auth new-key NAME --profile P`
    - name: support-bot          # who holds it: the audit log records this
      profile: support
      sha256: 2372e115...        # only the key's hash is kept
  oidc:                          # tokens from your identity provider
    issuer: https://login.example.com/
    audience: sql-warden         # what their aud claim must contain
    jwks_url: https://login.example.com/.well-known/jwks.json
    profile_claim: sql_warden_profile    # a claim that names the profile, or:
    # group_profiles: {data-analysts: support, dba: admin}   # profile by group
```

```console
$ sql-warden auth new-key support-bot --profile support
key: swk_...

Give it to support-bot: it is shown only this once, and can't be recovered.
```

| A request with                                    | Answer | Recorded as                    |
|---------------------------------------------------|--------|--------------------------------|
| no token, an unknown key, or a token that isn't valid (expired, for another service, signed with an unlisted key) | `401` | `UNAUTHENTICATED`, no profile |
| a valid token that gives no profile this server has, or groups that give two | `403` | `NO_PROFILE`, under the caller's name |
| an OIDC token while the provider's keys can't be fetched | `503` | `AUTH_UNAVAILABLE` |
| a token for a profile                             | the tools, as that profile | under the caller's name and profile |

A request that is turned away is never read: its body isn't parsed, and nothing runs. A
token never gets `default_profile`: a caller gets the profile their token names, or nothing.
Every record carries `identity` (an API key's name, or `oidc:<subject>`), shown by
`audit show` and filtered by `audit tail --identity NAME`. A connection belongs to the caller
who opened it: another token holding its `Mcp-Session-Id` gets `404`.

OIDC tokens are JWTs. Their signature is checked against the provider's published keys, and
so are `iss`, `aud` and `exp` (with 30 seconds' leeway for clocks). Only public-key
signatures are accepted (`RS256` and `ES256` by default; `algorithms` lists others):
`none`, and shared-secret ones like `HS256`, are refused, so whoever can read the keys
can't make a token. The keys are fetched when first needed and kept for an hour; a token
signed with a key not seen yet fetches them again, at most once a minute.

Serving every profile means every profile's role must pass the [startup
check](#defence-in-depth): `serve` doesn't start if any of them can write.

With `auth`, the server can listen beyond loopback. Set `server.host` (say `0.0.0.0`) and
list in `server.allowed_hosts` the names clients reach it by; requests for any other name
are refused. `server.allowed_origins` lists web pages that may call it from a browser.
sql-warden speaks plain HTTP, so put a proxy that terminates TLS in front of it, and let
clients reach it only through the proxy: every request carries its token. `serve` warns when
it listens beyond loopback.

```yaml
server:
  host: 0.0.0.0
  port: 8000
  allowed_hosts: [warden.example.com]
```

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
uv run sql-warden config validate --live   # then connects as each profile's role and checks it
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
database), `shape` (joins, nesting, LIMIT policy, function allow and deny lists, allowed types), `cost`
(`max_total_cost`), `budgets` (what one session may use), `masking` (the hmac key) and
`profiles`;
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

### Defence in depth

The checks decide what an agent may run. Under each of them the database holds the same line
by itself, so one wrong check is not enough to change or leak data:

| If this were wrong                 | this still holds                                                                                                  |
|------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| the shape check lets a write pass  | the role has no privilege to write; Postgres also runs every query in a `READ ONLY` transaction, through a cursor |
| the access check lets a table pass | a profile with its own `dsn` connects as a role that can't read it                                                |
| the LIMIT it adds is lost          | the engine stops fetching at the row cap                                                                          |
| the cost estimate is far too low   | the statement timeout cancels the query                                                                           |
| a string is read where it doesn't end | the query sent is written out again from what was read, and Postgres is set to read strings the standard way  |

The first of these depends on the role, so a server looks before it serves. It asks the
warehouse what its role can do, and doesn't start as one that can write:

```console
$ sql-warden serve --dsn postgresql://app:...@db.internal/warehouse
Error: profile all: role app can change the warehouse (db.internal/warehouse as app):
  it can INSERT, UPDATE, DELETE on public.orders
  it can create tables in schema public
sql-warden only serves as a role that can read and nothing more: then the database refuses a write even if every check here is wrong.
```

In Postgres, a role can write if it is a superuser, can `INSERT`, `UPDATE`, `DELETE` or
`TRUNCATE` on any table or view (one column is enough), can reset a sequence, can create
tables in a schema or schemas in the database, or can write files or run programs on the
server (`pg_write_server_files`, `pg_execute_server_program`). The roles it is a member of
count too, including ones it doesn't inherit from: `SET ROLE` would give it theirs. On
Postgres 14 and older every role can create tables in `public` until you
`REVOKE CREATE ON SCHEMA public FROM PUBLIC`. A role that passes:

```sql
CREATE ROLE warden_reader LOGIN PASSWORD '...';
GRANT USAGE ON SCHEMA public TO warden_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO warden_reader;
```

A server also doesn't start while the warehouse can't be reached: a role nobody could look
at is not one to serve as.

It warns, on stderr, when the role can read more than its profile allows. Then the database
is not backing the access check up, and only that check keeps the profile from the rest:

```console
$ sql-warden serve --profile support
warning: profile support allows less than its role can read. warden_reader can also read:
  table public.employee_salaries
Only the access check keeps the profile from these. Give the profile a dsn of its own, for a role granted just what the profile allows.
```

`sql-warden config validate --live` does the same for every profile at once, and exits 1 if a
server would not start for one of them, so a deploy can check the policy against the real
roles first:

```console
$ sql-warden config validate --live
  ...
  live:      public: role warden_public can only read
             support: role warden_reader can only read
               ! but more than the profile allows:
                 table public.employee_salaries
             admin: role warden_reader can only read
```

What it does not cover:

- **Later grants.** The role is looked at when the server starts, not again while it runs.
- **`query`, `check` and `tables` run by hand.** Whoever runs them holds the connection
  string and could use it without sql-warden; the server is the boundary, so the server is
  what is held to this.
- **Functions that write for their caller.** A `SECURITY DEFINER` function runs with its
  owner's privileges. The shape check refuses functions it doesn't know, and the read-only
  transaction stops a write inside one.
- **Snowflake outside the connection's database.** [Snowflake](#snowflake) says how the role
  is read there.

### Session budgets

A budget caps what one [session](#sessions) may use in total. No limit is set unless you set
it, for every profile or for one:

```yaml
budgets:
  max_refusals: 50          # for every profile
profiles:
  public:
    budgets:                # public's own; max_refusals: null would lift the limit above
      max_queries: 25
      max_total_cost: 50000
      max_rows_returned: 500
      max_refusals: 10
```

| Limit               | Counts                                                              |
|---------------------|---------------------------------------------------------------------|
| `max_queries`       | queries that were allowed and sent to the database                  |
| `max_total_cost`    | the sum of their estimated costs, in the units of `cost.max_total_cost` |
| `max_rows_returned` | rows returned, over all of them                                     |
| `max_refusals`      | requests a check refused, dry runs included                         |

- **A session that reaches a limit is done.** Its next request is refused with
  `BUDGET_EXHAUSTED` before any other check runs, so it learns nothing more and the database
  isn't asked to plan anything. That is what `max_refusals` is for: an agent can't try query
  after query until one gets through.
- **A query must fit what is left.** Its estimated cost is counted before it runs, and one
  that costs more than the session has left is refused with `COST_OVER_BUDGET`; a cheaper one
  may still fit. Counting and checking are one step, so requests arriving together can't
  spend the same last query.
- **Rows are counted afterwards**, since they are only known once the query has run. The query
  that takes a session past `max_rows_returned` still comes back; the next is refused.
- **Dry runs are free**, except that a refused one counts as a refusal. A dry run is told
  whether the query would fit.
- **Not every refusal counts.** The budget's own don't, nor do the ones that aren't the
  caller's doing: `COST_UNAVAILABLE`, `CATALOG_UNAVAILABLE`, `BUDGET_UNAVAILABLE`,
  `AUDIT_UNAVAILABLE`, `INTERNAL_ERROR`.

Each result says what the session has used (`budget`, and a `session budget:` line in the
CLI), and the `budget_status` tool says it at any time:

```text
$ uv run sql-warden --config warden.example.yaml check "select id, name from products"
✓ parse   1.8 ms
✓ shape   0.1 ms
✓ access  33.9 ms
✓ cost    6.3 ms
✓ budget  0.0 ms
→ allowed (profile public; dry run, nothing was executed)
  cost: 1.02 of 10,000 allowed (most of it: Seq Scan on products)
  note: added LIMIT 51 (row cap 50 + 1 to detect truncation)
  session budget: 0 of 25 queries, 0 of 50,000 cost, 0 of 500 rows, 0 of 10 refusals used
  would run: SELECT id, name FROM public.products LIMIT 51
```

#### Budgets outlive the server, and are shared by every server

A server keeps budgets in the audit database, next to the log: what each session has used is
one row there, charged in one locked transaction per request. Every server recording to that
database charges the same rows, so a session (or a caller, below) gets no more by reaching
another replica behind a load balancer, and requests arriving at once on different servers
can't spend the same last query. The first time a session is charged, its row starts from
what the audit log says it used: its queries that were sent to the database with their
estimated costs and rows, and its counted refusals, under the same profile. So CLI calls
given the same `--session` share one budget, though each is its own process:

```text
$ uv run sql-warden --config warden.example.yaml query "select id from products limit 3" --session nightly-2026-11-12
...
session budget: 1 of 25 queries, 0.06 of 50,000 cost, 3 of 500 rows, 0 of 10 refusals used
$ uv run sql-warden --config warden.example.yaml query "select id from products limit 3" --session nightly-2026-11-12
...
session budget: 2 of 25 queries, 0.12 of 50,000 cost, 6 of 500 rows, 0 of 10 refusals used
```

- **A name is one session for good.** Its budget never starts again, however old its
  records, so give each run its own name, say with the date in it.
- **If the usage can't be read, nothing runs**: the query is refused with
  `BUDGET_UNAVAILABLE`. A profile without limits never reads it, and keeps nothing there.
- **An agent's session doesn't survive a restart anyway.** Over stdio the session is the
  server process, and over HTTP it is the connection, which a restarted server has forgotten:
  the agent reconnects and gets a new session, with a new budget. A caller with a token is
  held to their own budget as well, which doesn't start again (next).
- The tables are `session_usage` and `caller_charges`, created with `audit_events`. The role
  servers connect to the audit database as needs to update them, which it doesn't need for
  the log itself.

#### Budgets per caller

A session's budget starts afresh with every connection. A caller with a
[token](#authentication) can also be held to a budget of their own, over a rolling window,
across all their sessions: connecting again doesn't give them more.

```yaml
identity_budgets:           # for every caller with a token
  window_hours: 24          # "in any 24 hours"; the default
  max_queries: 500
  max_refusals: 50
profiles:
  public:
    identity_budgets:       # public's callers', merged with the above as budgets are
      max_rows_returned: 5000
```

The limits are the session budget's four, counted the same way. A request is held to both
budgets, its session's and its caller's, in one step: whichever runs out first refuses, and
the refusal says which (`this session's budget is used up` or `web-agent's budget for any 24
hours is used up`). Use counts while it is younger than the window, so a caller who reached a
limit can go on once enough of their earlier use is older than that. Each result's `budget`
has the caller's as `caller`, beside the session's, and so does `budget_status`.

Only callers with a token have one, so `identity_budgets` needs an `auth` section:
`config validate` says so rather than let it be ignored. A charge is kept as a row of
`caller_charges`, and deleted once it is older than the window.

### Snowflake

The warehouse can be Snowflake. The audit database stays Postgres either way. Install the
connector, which is an optional extra, and say so in `warden.yaml`:

```bash
pip install 'sql-warden[snowflake]'       # in this repo, uv sync already has it
```

```yaml
warehouse:
  engine: snowflake
  dsn: snowflake://WARDEN_READER:${SNOWFLAKE_PASSWORD}@myorg-myaccount/WAREHOUSE/PUBLIC?warehouse=WARDEN_XS&role=WARDEN_READER
  statement_timeout_ms: 5000     # Snowflake counts whole seconds: rounded up
  max_rows: 100
cost:
  max_total_cost: 10737418240    # bytes a query may scan; this is the default, 10 GiB
profiles:
  support:
    tables:
      PUBLIC.CUSTOMERS: "*"      # names as Snowflake stores them: upper case
      PUBLIC.ORDERS: [ID, CUSTOMER_ID, QUANTITY]
    masks:
      PUBLIC.CUSTOMERS.SSN: redact
```

The connection string is `snowflake://USER:PASSWORD@ACCOUNT/DATABASE/SCHEMA`, with
`warehouse`, `role`, `authenticator`, `private_key_file` and `private_key_file_pwd` as
options after `?`. A password or programmatic access token goes in the password's place; for
a key pair, leave it out and give `private_key_file`. Characters a URL can't hold are
percent-encoded. A profile's own `dsn` works as for Postgres: usually another role.

What is different from Postgres:

- **Names are upper case.** Snowflake stores an unquoted name in upper case, and profiles and
  masks name tables and columns as they are stored. `config validate` points out names that
  aren't. A table named without a schema is looked up in the connection's schema.
- **The cost is bytes.** `EXPLAIN` gives the bytes in the partitions a query may scan, so that
  is what `cost.max_total_cost` and a budget's `max_total_cost` count, and a refusal says "this
  query may scan 6.4 GiB, over profile support's limit of 1 GiB". There is no row estimate.
  It measures reading, not work: a join that multiplies two small tables scans little. The
  statement timeout is what stops that one.
- **Read-only is the role's job.** Snowflake has no read-only session to ask for, so connect
  as a role granted only `USAGE` and `SELECT`. The checks refuse everything but a `SELECT`
  either way; the role is what holds if a check is wrong. A server
  [looks at it before it starts](#defence-in-depth): it doesn't serve as a role that holds
  `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `OWNERSHIP` or any `CREATE` in the connection's
  database, itself or through a role granted to it (or `PUBLIC`), or that holds
  `ACCOUNTADMIN`, `SECURITYADMIN`, `SYSADMIN`, `USERADMIN` or `ORGADMIN`. Each session also
  starts with `USE SECONDARY ROLES NONE`, so a user's other roles lend it nothing:

  ```sql
  CREATE ROLE WARDEN_READER;
  GRANT USAGE ON WAREHOUSE WARDEN_XS TO ROLE WARDEN_READER;
  GRANT USAGE ON DATABASE WAREHOUSE TO ROLE WARDEN_READER;
  GRANT USAGE ON SCHEMA WAREHOUSE.PUBLIC TO ROLE WARDEN_READER;
  GRANT SELECT ON ALL TABLES IN SCHEMA WAREHOUSE.PUBLIC TO ROLE WARDEN_READER;
  ```
- **Snowflake enforces the rest too:** the statement timeout
  (`STATEMENT_TIMEOUT_IN_SECONDS`), one statement per request (`MULTI_STATEMENT_COUNT`), and
  the row cap (`ROWS_PER_RESULTSET`).
- **Queries are tagged.** Each query's `QUERY_TAG` is `sql-warden <audit_id>`, so Snowflake's
  query history and sql-warden's audit log can be matched record for record.

How far it is tested: against a stand-in for the connector (every `pytest`), and on
[fakesnow](https://github.com/tekumara/fakesnow), which runs Snowflake SQL on DuckDB. fakesnow
has no planner, so the cost check is tested on saved plans, one from Snowflake's documentation
and the rest written in its shape. **It has not yet run against a real account.** The tests
for that are written and only read:

```bash
uv run --with 'fakesnow==0.12.1' --with 'snowflake-connector-python<5' pytest tests/fakesnow
SNOWFLAKE_DSN='snowflake://...' uv run pytest -m snowflake
```

fakesnow is kept out of the project's own dependencies because it pins the SQL parser to an
older release and needs a connector before version 5; the first command lays it over the
environment for that run only.

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
