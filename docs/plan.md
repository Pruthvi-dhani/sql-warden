# sql-warden — Implementation Plan

## Context
sql-warden lets an AI agent query a real database safely. The server enforces the rules, so the
agent's prompt doesn't have to be trusted. Every query passes through a pipeline of checks:
**shape**, **access** (tables/columns), **cost** (from the database planner), **budget**, and
then execution with **masking**. Any check can refuse the query with a specific code and reason.
Every request is written to a **separate audit DB**.

Stack: Python 3.12 (uv, hatchling, src layout), sqlglot, psycopg 3, pydantic, click, the `mcp`
SDK, PostgreSQL, Snowflake. Quality gates: ruff, mypy strict, pytest with Testcontainers.

Decisions made:
- **Interface:** an MCP server for agents (stdio, plus local-only HTTP for the test portal), and
  a `sql-warden` CLI for playing with it by hand. Agents reach the service only through MCP;
  there is no REST API. A REST layer could be added later on top of the same `Warden` facade.
- **"Approved shape"** means structural AST rules, not query templates.
- **What runs is what was checked.** An allowed query is regenerated from the sqlglot tree the
  checks approved, with comments dropped. The raw text never reaches the database, so a parser
  disagreement or a comment trick can't smuggle SQL past the checks.
- **Audit DB is always Postgres**, on a separate instance from the warehouse, whatever the
  warehouse engine is.
- **Profiles, not per-feature rule sets.** Who may see what is a named **profile** in
  `warden.yaml` (e.g. `public` for an agent released to customers, `admin` for internal
  admins), holding that caller's tables, columns, masks, cost limits and budgets. A server is
  tied to a profile by whoever deploys it (`--profile`, Phase 2) and later by the caller's
  token (Phase 9.2); the agent itself can never choose or change its profile. Each profile can
  also connect as its own database role, so Postgres enforces the same split.
- **Snowflake:** built on the shared engine protocol. There is no Snowflake account yet, so it is
  tested with fakesnow and recorded EXPLAIN fixtures. Live tests run only when `SNOWFLAKE_*` env
  vars are set.

**Rule for every point below:** each point is one commit. Each ships code plus tests, and leaves
`ruff check`, `mypy` (strict) and `pytest` green. From Phase 0 on, there is always something to
run.

## Architecture
Built so far:
```
src/sql_warden/
  config.py          # pydantic policy model, loads warden.yaml (extra="forbid", env interpolation)
  models.py          # RefusalCode, Refusal(code, reason), TraceEntry, Decision(trace, sql, rewrites), QueryOutcome
  pipeline/
    base.py          # Check protocol, CheckContext, Pipeline (ordered, short-circuit, per-check trace, fail-closed)
    parse.py         # ParseCheck: parses once with sqlglot, readable errors
    shape.py         # ShapeCheck: structural rules + LIMIT rewrite
  catalog.py         # Catalog: the role's tables and columns, cached, as a sqlglot schema
  engines/
    base.py          # Engine protocol (max_rows, execute(sql) -> Result, tables()), engine errors
    postgres.py      # read-only transaction, statement timeout, row cap via server-side cursor
  warden.py          # Warden facade: parse -> checks -> regenerate SQL -> execute
  server.py          # MCP tools (run_query, check_query, list_tables); stdio + loopback HTTP
  render.py          # CLI text output
  cli.py             # click: query / check / serve / config validate
dev/  docker-compose.yml (project sql-warden-demo), warehouse_seed.sql
warden.example.yaml
tests/unit/  tests/integration/ (marker: integration)
```
Still to come:
```
src/sql_warden/
  pipeline/  access.py  cost.py  budget.py  masking.py  lineage.py
  engines/   snowflake.py          # plus explain() on the Engine protocol
  profiles.py                      # active profile: its tables/columns, DSN, later masks and limits
  audit/     schema.sql, sink.py   # AuditSink protocol, PostgresAuditSink, MemoryAuditSink
  sessions.py                      # session + budget store
tests/portal/  tests/snowflake/ (marker: snowflake)
```
The SQL is parsed once with sqlglot, and every check reads that same AST. EXPLAIN runs only
after shape and access have passed, so unvetted SQL never reaches the database, not even through
the planner. Execution always runs inside a `READ ONLY` transaction with `statement_timeout` and
a row cap, as defence in depth.

---

## Phase 0 — Foundation & a runnable skeleton
**0.1 Project scaffolding** ✅ done (`3807ac7`)
- `pyproject.toml` (hatchling, src layout, `sql-warden` console script, deps), ruff config,
  `mypy strict`, and pytest config (markers `integration`, `snowflake`). `.gitignore` and the
  README dev-setup section.
- Tests: `test_package.py` checks the import and `__version__`.

**0.2 Demo stack with seeded data** ✅ done (`79c377b`)
- `dev/docker-compose.yml` runs two Postgres containers: `warehouse` on :5433 and `audit` on
  :5434.
- `dev/warehouse_seed.sql` is deterministic, built with `generate_series`. It creates
  `customers` (email, phone, ssn), `orders` (1M rows, to make cost checks meaningful),
  `products`, and an off-limits `employee_salaries` table. It also creates a read-only
  `warden_reader` role.
- Tests: an integration Testcontainers fixture (session-scoped) loads the same seed file and
  asserts row counts. Every later integration test reuses it.

**0.3 Engine protocol + Postgres engine + `sql-warden query`** ✅ done (`087371e`)
- `engines/base.py` defines the protocol and `Result`. `engines/postgres.py` executes inside a
  read-only transaction with `statement_timeout`, and stops fetching at `max_rows` with a
  `truncated` flag.
- The CLI `query "<sql>"` prints a table.
- Tests: result formatting and settings (unit); a SELECT works, an INSERT is rejected by the
  read-only transaction, `pg_sleep` past the timeout is cancelled, truncation works
  (integration).

## Phase 1 — Checks, policy, MCP server and test portal
By the end of this phase an agent (Claude Code) and the browser portal can both use sql-warden,
with parse and shape checks enforced. Every point changes what you can see in the CLI, the
portal, or Claude.

**1.1 Decision model, pipeline, `Warden`, and `sql-warden check`** ✅ done (`39d34b7`)
- `models.py` holds `RefusalCode`, `Refusal`, `TraceEntry`, `Decision`, `QueryOutcome`.
  `pipeline/base.py` holds the Check protocol and the Pipeline runner, which stops at the first
  refusal, returns a full trace, and fails closed (a crashing check → `INTERNAL_ERROR`).
- The `Warden` facade runs parse → checks → execute. The parse check (sqlglot) refuses
  malformed or empty SQL with readable reasons. `sql-warden check` is a dry run; `query` goes
  through the pipeline.

**1.2 Policy config + `sql-warden config validate`** ✅ done (`a1ca2ae`)
- `config.py` loads `warden.yaml` into frozen pydantic models, with `${VAR}` /
  `${VAR:-default}` env interpolation for secrets. Unknown keys are errors, and every problem is
  reported at once with its location.
- Only the `warehouse` section (engine, dsn, statement timeout, row cap, connect timeout)
  exists so far. Each later section is added in the same point as the check that enforces it,
  so a rule in the file is never silently ignored.
- Precedence: command-line flags and `SQL_WARDEN_DSN` > `--config` / `SQL_WARDEN_CONFIG` >
  `./warden.yaml` > built-in defaults for the demo stack.
- `sql-warden config validate` checks the file without connecting and never prints the
  password. Ships `warden.example.yaml`, which matches the demo stack.

**1.3 Shape check (sqlglot)** ✅ done (`2fc5821`)
- Refuses, each with its own code:
  - more than one statement (`MULTIPLE_STATEMENTS`);
  - anything but SELECT/UNION/CTE queries (`NOT_A_SELECT`);
  - data-modifying CTEs, `SELECT … INTO`, `FOR UPDATE`/`SHARE` (`NOT_READ_ONLY`);
  - functions sqlglot doesn't know as standard SQL, unless they are in
    `shape.allowed_functions` (`FUNCTION_NOT_ALLOWED`);
  - built-in denied functions (`pg_sleep*`, `pg_read_file`, `lo_*`, `dblink*`, `set_config`,
    `current_setting`, `query_to_xml*`, …), which can't be allowlisted, plus
    `shape.denied_functions` glob patterns;
  - more than `max_joins` joins (`TOO_MANY_JOINS`) or subqueries/CTEs nested deeper than
    `max_subquery_depth` (`SUBQUERY_TOO_DEEP`), counted with sqlglot scopes;
  - LIMITs it can't enforce (`LIMIT ALL`, expressions, `FETCH … PERCENT`/`WITH TIES`:
    `INVALID_LIMIT`).
- LIMIT policy (`shape.limit`):
  - `inject` (default) adds a LIMIT when there is none and lowers one above the row cap.
  - `require` refuses instead (`LIMIT_REQUIRED`, `LIMIT_TOO_HIGH`).
  - The injected LIMIT is the row cap **plus one**, so the engine can still report truncation.
- The `Warden` regenerates the approved tree (comments dropped) and executes that. The
  `Decision` carries the final SQL and rewrite notes. `check` shows "would run: …", and `query`
  prints a `note:` under the table.
- Tests: about 110 parametrized good and bad SQL strings → expected code and reason; the LIMIT
  rewrite SQL. Integration: regenerated SQL for Postgres-specific syntax still runs, truncation
  survives the rewrite, and shape refusals stop writes even for the admin role.

**1.4 MCP server (stdio + local HTTP)** ✅ done (`fd769d4`)
- `server.py` uses `MCPServer` with these tools: `run_query(sql)`, `check_query(sql)` (dry
  run), and `list_tables()`. A refusal comes back as a structured result
  (`{refused: true, check, code, reason, trace}`) rather than an opaque error, so the agent can
  correct itself. Allowed results include the executed SQL and rewrite notes.
- `sql-warden serve` runs it over stdio, the default. `sql-warden serve --transport http` runs
  streamable HTTP at `/mcp`. It is **local dev only**: it binds to `127.0.0.1` and refuses any
  other host, MCP's DNS-rebinding/Origin protection is on, and there is no auth (auth stays in
  Phase 9).
- `server.py` exposes a factory for the MCP HTTP ASGI app (`create_http_app(warden)`), so other
  code can mount it. The test portal in 1.5 does this.
- `list_tables` reads `information_schema` through a new `Engine.tables()`, which only shows
  what the warehouse role can read. 2.1 builds the cached catalog on top of it.
- `Warden.run` reports engine errors in the outcome instead of raising, so the decision and
  trace survive a database failure (and 3.2 can audit it). `run_query` goes through it.
- `run_query` marks refusals and database errors as tool errors; `check_query` returns a
  refusal as a normal answer. Database values become JSON: numerics as exact strings, times as
  ISO 8601.
- Tests: an in-process MCP client checks the tool list, allowed results, refusal and error
  payloads. Over real transports: an MCP client against uvicorn on a free port, the plain
  JSON-RPC `initialize` a browser sends, foreign `Origin` (403) and `Host` (421) rejected, and
  `python -m sql_warden serve` over stdio in a subprocess. The server refuses non-loopback
  hosts. Integration: `tables()` and `run_query` against the seeded warehouse.

**1.5 Test portal (`tests/portal/`)** ✅ done (`9a1a230`)
- A browser page for manual testing. It's a testing tool, so it lives in the tests tree and is
  **not shipped** in the `sql_warden` package:
  ```
  tests/portal/
    index.html       # the page: one file, vanilla JS, no build step
    app.py           # create_portal_app(): create_http_app() at /mcp, index.html at /
    __main__.py      # launcher (click), same config and flags as sql-warden
    test_portal.py   # automated tests for the launcher + the page's JSON-RPC sequence
    README.md        # how to run it, what each panel shows
  ```
- Run it with `uv run python -m tests.portal [--dsn …] [--port 8765]`. It binds to 127.0.0.1
  and opens the browser. The page and `/mcp` share one origin, so no CORS is needed.
- The page talks **real MCP** (JSON-RPC `initialize` → `tools/call` with `Mcp-Session-Id`), so
  it shows exactly what an agent receives. It has:
  - a SQL editor with Check and Run buttons (Ctrl/Cmd+Enter runs);
  - the per-check trace (✓/✗, code, reason, timings), the SQL that ran and any rewrite notes,
    and a results table (truncation flagged);
  - a table list from `list_tables`, and a query history (localStorage);
  - a console panel with the raw request and response JSON for every call.
  Later phases add panels as features arrive: masked columns, cost estimates, budgets, audit
  tail.
- Also: example queries for each kind of refusal, and `?sql=…&tool=run|check` to bookmark a
  test query. An expired session (404) makes the page reconnect on its own.
- Tests: HTTP tests serve the page and replay its JSON-RPC sequence through `/mcp` (handshake,
  run, check, refusal, 404 on a stale session, foreign origin refused), and check that the page
  only calls tools the server has. An integration test runs the portal against the
  Testcontainer. `tests/support.py` holds the shared uvicorn-in-a-thread helper. The page's JS
  stays deliberately thin and is checked by hand (it was also checked with headless Chrome
  screenshots against the demo stack); browser automation can come later if it grows.

**1.6 Claude Code hookup** ✅ done (`f3bce20`)
- Adds a `.mcp.json.example` and a README walkthrough (`claude mcp add …`), plus an integration
  test that starts the stdio server as a subprocess against the Testcontainer.
- The example runs `uv run --directory ${CLAUDE_PROJECT_DIR:-.} sql-warden serve`, so the
  server starts in the repo and reads `./warden.yaml` like the CLI. `.mcp.json` itself is
  git-ignored, so the repo never asks a cloned checkout to approve a server.
- The integration test reads `.mcp.json.example`, expands it the way Claude Code does, and
  launches exactly that command: tools, instructions, `list_tables`, a run that honours the
  config's row cap, and refusals all arrive over stdio.
- **Play:** connect Claude Code to sql-warden and ask it questions about the demo data. Each
  check added after this point shows up in Claude and in the portal immediately.

**1.7 CLI polish + end-to-end tests** ✅ done (`337b6a7`)
- Strips the internal `DECLARE … CURSOR FOR` wrapper from database error messages. The engine
  rebuilds the message from Postgres's diagnostics (message, DETAIL, HINT), with a caret under
  the error position shifted into the SQL as sent, so the CLI, MCP and the portal all show it.
- Adds `--json` output (the same structured Decision that MCP returns, as one line) and
  meaningful exit codes (0 allowed, 2 refused, 1 error). Click's usage errors would exit 2, so
  the CLI group moves them to 1: exit 2 always means a check refused the query.
- Tests: CLI snapshot and exit-code tests, and the CLI's `--json` compared with `run_query`'s
  structured result. An integration test against the Testcontainer runs one allowed and one
  refused query through the real engine, plus a database error with and without `--json`.
- Note: until Phase 2 there are no table or column rules. A well-formed SELECT can read
  anything `warden_reader` can see.

## Phase 2 — Profiles: table & column access control
Goal: an agent released to customers sees only public data, an admin agent sees everything, and
neither can change which one it is. Example policy:
```yaml
default_profile: public
profiles:
  public:                                   # the agent released to customers
    dsn: ${WARDEN_PUBLIC_DSN}               # optional: a DB role that can only read these
    tables:
      public.products: [id, name, price_cents]
  admin:                                    # internal admins
    tables: "*"                             # every table and column the role can read
```

**2.1 Catalog introspection** ✅ done
- `catalog.py` builds on `Engine.tables()` (from 1.4): caches the result and turns it into a
  sqlglot schema.
- `Catalog` reads lazily and reuses a read for 60 s (`refresh()` forces a new one); concurrent
  callers share one read, and a failed read is not cached. `Warden.tables()`, and so
  `list_tables`, now come from it.
- Names are kept exactly as Postgres stores them and the sqlglot `MappingSchema` is built with
  `normalize=False`, so qualifying a query resolves names like Postgres: `PRODUCTS` finds
  `products`, `"MixedCase"` finds only `MixedCase`, `"ID"` finds nothing. Types sqlglot can't
  parse (e.g. `tsvector`) become `UNKNOWN`; the column is still listed.
- Tests: unit tests with a fake catalog, an integration test against the seeded DB.

**2.2 Profiles in the policy + `--profile`**
- A `profiles:` section replaces a single `tables:` section. Each profile has `tables`: either
  `"*"`, or a map of schema-qualified table → `"*"` or a list of columns. Each profile may set
  its own `dsn`; without one it uses `warehouse.dsn`. `default_profile` names the profile used
  when none is picked.
- A server is tied to one profile: `--profile NAME` or `SQL_WARDEN_PROFILE` on `serve`,
  `query` and `check` picks it, else `default_profile`. An unknown profile is a startup error,
  never a fallback.
- With no `profiles:` section there is one implicit `all` profile allowing every table (the
  Phase 1 behaviour), so existing configs keep working; `config validate` says so loudly, and
  9.1 refuses to serve beyond loopback without real profiles.
- The active profile is part of every Decision: the CLI shows it, `--json` and the MCP results
  carry `profile`, and the server's instructions name it. `config validate` lists each
  profile's tables and whether it has its own DSN.
- Demo stack: the seed adds a `warden_public` role with `SELECT` only on `products`, and
  `warden.example.yaml` ships the `public` and `admin` profiles above (`public` connects as
  `warden_public`). Picking up the new role needs a reseed (`down -v`, then `up -d`).
- Tests: config unit tests (unknown keys, an unknown default profile, a bad table spec, every
  problem reported at once); profile selection precedence (flag > env > default); a profile's
  own DSN reaches the engine.

**2.3 Access check**
- `sqlglot.optimizer.qualify` with the catalog resolves aliases, CTEs, subqueries, quoting and
  case. The check collects every (table, column) referenced in any clause and refuses
  `TABLE_NOT_ALLOWED` or `COLUMN_NOT_ALLOWED` against the **active profile**, naming the
  offender and the profile.
- `SELECT *` is expanded when every column is approved. Otherwise it is refused with
  `STAR_NOT_ALLOWED`, which lists the permitted columns.
- Tests: aliases, a CTE that shadows a real table name, a correlated subquery,
  schema-qualified and quoted names, an unknown column, a column referenced only in
  WHERE/ORDER BY; the same query allowed under `admin` and refused under `public`.
  Integration: the `public` profile's own DB role refuses `employee_salaries` even if the
  access check is bypassed (defence in depth).

**2.4 Discoverability**
- `list_tables` and the new `describe_table` (MCP and CLI `tables`) show only what the active
  profile allows, with masked columns flagged once Phase 5 lands. A `public` agent never
  learns that `employee_salaries` exists.
- Tests: unit tests (unapproved objects never appear, per profile) and a CLI snapshot.

**2.5 Portal: profile picker**
- The portal serves one MCP endpoint per profile (`/p/<profile>/mcp`, each its own `Warden`),
  and a picker in the header switches between them, starting a new session. The Tables panel
  follows the picked profile.
- A **Compare** button runs the current query under every profile and shows one row each
  (allowed / refused with code and reason), so `public` and `admin` can be seen side by side.
- Tests: the portal HTTP tests call each profile's endpoint and get that profile's tables and
  decisions; an integration test runs the comparison against the Testcontainer.

## Phase 3 — Audit database
**3.1 Audit sink**
- `audit/schema.sql` creates `audit_events` with these columns: id, ts, session_id, client,
  profile, sql (as sent), executed_sql (as regenerated and run), rewrites, decision, check, code,
  reason, cost_estimate, rows_returned, masked_columns, duration_ms, and the full trace as
  jsonb. The schema is applied idempotently at startup. Adds the `audit` config section.
- There is an `AuditSink` protocol with Postgres and in-memory implementations.
- Tests: integration with a second Testcontainer.

**3.2 Record every request, fail-closed**
- Every outcome writes exactly one event: allowed, refused, execution error, timeout. If the
  audit write fails, the query is refused with `AUDIT_UNAVAILABLE`, and the database is never
  queried without an audit record.
- Tests: a unit test with a failing sink; integration tests where one call produces one row
  with the right fields.

**3.3 `sql-warden audit tail|show <id>`**
- Tests: CLI output against seeded audit rows.

## Phase 4 — Cost gate via the planner
**4.1 `explain()` for Postgres**
- Runs `EXPLAIN (FORMAT JSON)`, never ANALYZE, inside a read-only transaction, on the
  regenerated SQL, and returns `CostEstimate(total_cost, est_rows, top_node, raw)`.
- Tests: integration on the 1M-row `orders` table. An indexed lookup is cheap, a cross join is
  expensive.

**4.2 Cost check**
- Uses the policy values `max_total_cost` and `max_estimated_rows` (new `cost` config
  section, with per-profile overrides, so `public` can be held to tighter limits than `admin`). It refuses with `COST_TOO_HIGH`, giving the estimate against the limit and the
  dominant plan node (e.g. "Seq Scan on orders"). The estimate is written to the audit record.
- Tests: unit tests with a fake engine at the boundaries (equal to the limit passes);
  integration tests where the cartesian join is refused and the filtered query passes.

## Phase 5 — Masking sensitive columns
**5.1 Mask strategies**
- Strategies: `redact`, `partial` (e.g. last 4), `hmac` (keyed and deterministic, so masked
  values can still be joined and grouped), and `null`. They handle NULL and non-string types.
  Masks live under each profile (`profiles.<name>.masks`), so `admin` can see an unmasked
  column that another profile sees masked.
- Tests: unit tests, including a test that HMAC output is stable for one key and differs
  across keys.

**5.2 Output lineage**
- `lineage.py` maps each output column back to its source columns, through aliases,
  expressions, CTEs and UNIONs. Any output derived from a masked column is masked.
- If a masked column is used in WHERE/JOIN/GROUP BY/ORDER BY, the query is refused with
  `MASKED_COLUMN_IN_PREDICATE` by default (configurable per column). This blocks inference
  attacks such as `WHERE ssn LIKE '123%'`. `count(col)` is allowed.
- Tests: `upper(email)`, `email AS e`, concatenation, CTE pass-through, a union branch, and the
  predicate-leak cases.

**5.3 Apply masks at execution**
- The masks run on result rows in `Warden`. Masked columns are listed in the result metadata
  and in the audit record.
- Tests: an integration test on `customers.ssn` and `email`.

## Phase 6 — Sessions & query budgets
**6.1 Session store**
- Each session has a `session_id` (per MCP connection; the CLI takes `--session`). Budgets:
  `max_queries`, `max_total_cost`, `max_rows_returned`, and `max_refusals`, which stops an
  agent from brute-forcing its way through the checks. Limits come from a `budgets` section
  with per-profile overrides. The store is thread-safe and in-memory,
  behind a `SessionStore` protocol so that 9.3 can swap in a Postgres-backed store.
- Tests: unit tests, including concurrent increments.

**6.2 Budget check + post-execution accounting**
- Before running, the check refuses `BUDGET_EXHAUSTED` with the remaining budget. After
  running, it charges the actual cost and rows. A new `budget_status` MCP tool shows the state.
- Tests: unit tests (the last query allowed, the next refused); an MCP tool test.

**6.3 Budgets survive restarts**
- Session usage is rebuilt from the audit DB when the server starts.
- Tests: an integration test that restarts the Warden and finds the budget still used.

## Phase 7 — Snowflake engine
The audit DB is always Postgres, whatever the warehouse engine is. Config sets
`warehouse.engine: postgres | snowflake`, and `audit.dsn` is always a Postgres DSN. In Snowflake
mode, local dev runs only the compose `audit` container, and the warehouse is the Snowflake
account.

**7.1 Dialect-aware checks**
- The dialect comes from config. The shape, access and lineage tests are parametrized over
  `postgres` and `snowflake`. The built-in function denylist (Postgres-only today) becomes
  per-dialect, adding Snowflake ones such as `SYSTEM$…`, and the LIMIT rewrite handles `TOP`.

**7.2 `SnowflakeEngine`** (optional `[snowflake]` extra)
- Execution uses a read-only role, `STATEMENT_TIMEOUT_IN_SECONDS`, and a `QUERY_TAG` set to the
  audit id. `explain()` runs `EXPLAIN USING JSON` and turns
  `bytesAssigned`/`partitionsAssigned` into a CostEstimate. The catalog comes from
  `INFORMATION_SCHEMA`. The connector sits behind a small typed wrapper so `mypy --strict` stays
  clean.
- Tests, in three tiers:
  - **fakesnow** (dev dependency; runs on every `pytest` and in CI with no account or Docker): a
    fixture patches `snowflake.connector` and loads a Snowflake-dialect copy of the demo seed.
    It covers `SnowflakeEngine` execution, catalog introspection, LIMIT/row cap, masking and
    audit, end to end through `Warden`.
  - **Saved EXPLAIN fixtures**: unit tests that turn recorded `EXPLAIN USING JSON` output into
    `CostEstimate` values and check the cost limits. fakesnow can't produce real plans, so this
    is how the cost check is tested.
  - **Live**: `tests/snowflake/`, marker `snowflake`, skipped unless `SNOWFLAKE_*` env vars are
    set. It confirms the cost check and the read-only role against a real account.

## Phase 8 — Hardening & CI
**8.1 Startup safety checks**
- On startup the server refuses to run if the configured DB role can write (Postgres: checks
  `has_table_privilege` for INSERT/UPDATE/DELETE), checking every profile's DSN. It also warns
  when a profile's role can read tables the profile doesn't allow, i.e. when the database isn't
  backing up the access check. The README gets a "defence in depth" section.
- Tests: integration with the superuser (refused) and with `warden_reader` (starts).

**8.2 Adversarial corpus**
- `tests/unit/test_adversarial.py` covers comment and Unicode tricks, nested forbidden
  functions, `COPY`, `DO $$`, `EXPLAIN ANALYZE` smuggling, stacked statements, `set_config` in a
  subquery, and casting tricks.

**8.3 CI** ✅ done early
- A GitHub Actions workflow runs ruff, mypy, the unit tests and the integration tests (Docker
  is available on ubuntu runners).
- `.github/workflows/ci.yml` runs on every push to `main` and every pull request, as three
  parallel jobs: lint (`ruff check`, `ruff format --check`, `mypy` strict), unit tests
  (`-m "not integration and not snowflake"`), and integration tests against Testcontainers
  Postgres (`-m "integration and not snowflake"`). The live Snowflake tests (Phase 7) stay out
  of CI until there is an account to run them against.

## Phase 9 — Production: sql-warden as a central service
Target setup: agents connect over HTTPS with a token, and only the warden holds database
credentials (pulled from a secrets manager). The warehouse is a Postgres read replica or
Snowflake (dedicated XS warehouse + resource monitor). The audit DB is a managed Postgres in a
separate account. `warden.yaml` lives in git and changes through PR review. Scripts use the
CLI.

**9.1 Production HTTP transport**
- Builds on the local-only HTTP mode from 1.4: lifts the loopback-only restriction (only
  together with 9.2 auth, and only when the policy defines real profiles rather than the
  implicit `all`), adds configurable host/port and TLS-terminating proxy guidance. Each
  MCP session id maps to a warden session.
- Tests: an in-process HTTP MCP client session covers the tool list, run, refuse, and session
  isolation between two clients.

**9.2 Authentication → profiles**
- Bearer tokens: either static hashed API keys in config, or OIDC/JWT validated with `pyjwt`
  against JWKS. Each token maps to one of the **profiles from Phase 2** (an API key names its
  profile; for OIDC a claim or group maps to a profile name). There is no separate per-client
  policy format: the profile is the policy, and one server now serves every profile, each
  request using its token's profile (and that profile's DSN).
- A token with no profile mapping is refused (403), never given `default_profile`. The
  identity and profile are recorded on every audit event. Unauthenticated → 401, with nothing
  executed and the attempt audited. `--profile` stays for stdio and local use only.
- Tests: unit tests for token validation (expired, wrong audience, unknown key) and profile
  resolution (unmapped token refused). An HTTP test checks that a `public` token and an
  `admin` token see different tables and get different decisions for the same query.

**9.3 Shared budget state across replicas**
- `PostgresSessionStore` lives in the audit DB and uses atomic `UPDATE … RETURNING` counters,
  so budgets hold when N replicas serve the same session. Works with sticky sessions or the
  SDK's stateless HTTP mode.
- **Per-identity budgets:** a rolling window (e.g. per 24h) per token/user, in addition to
  per-session budgets. Session ids are created by the server, so session-only budgets could be
  reset just by reconnecting. Both are checked; the stricter one wins, and the refusal says
  which one ran out.
- Tests: an integration test runs two Warden instances against one audit container with
  concurrent queries and never exceeds the budget. A reconnect test checks that a new session
  under the same identity is still refused once the identity budget is used up.

**9.4 Container image + health checks + metrics**
- A multi-stage `Dockerfile` (non-root, slim). `/healthz` is the liveness check; `/readyz`
  checks that the warehouse and audit are reachable and the role is read-only. Prometheus
  `/metrics` covers requests and refusals by code, the cost histogram, latency and audit-write
  failures. Shutdown is graceful.
- Tests: unit tests for the metrics counters. An integration test builds the image and runs it
  with Testcontainers against the warehouse and audit containers, then hits health, readiness
  and one MCP call.

**9.5 Config validation & hot reload**
- `sql-warden config validate` gains `--live`, which checks the policy against the live catalog
  (approved columns that no longer exist, masks on unknown columns). A policy reload on SIGHUP
  is atomic; a bad config keeps the old policy and logs the error.
- Tests: unit tests for the reload swap and for rejecting a bad config. An integration test for
  catalog drift.

**9.6 Hardened audit**
- Deployment SQL for an INSERT-only warden role on `audit_events` (no UPDATE/DELETE) and a
  retention job (`sql-warden audit prune --older-than`, run by a separately privileged role).
  Optional one-way export to Snowflake for analytics. The deployment guide goes in
  `docs/deploy.md` (k8s/ECS examples, secrets, network policy so only the warden can reach the
  warehouse).
- Tests: an integration test where the warden role's UPDATE/DELETE on audit is denied, and a
  prune test.

---

**9.7 Per-customer row filtering** (only if customers need their own rows)
- For an agent released to customers that must show each customer only *their* rows (e.g.
  "my orders"), not just shared public tables. Needs 9.2, because the customer id must come
  from an authenticated token, never from the agent or the SQL.
- A profile can give a table a row filter, e.g. `public.orders: {columns: [...], rows:
  "customer_id = :customer_id"}`, where `:customer_id` is bound from a token claim. The check
  rewrites every reference to that table, in joins, subqueries, CTEs and UNION branches, into a
  filtered subquery, so the filter can't be escaped with `OR`, aliases or a second reference.
  The rewrite note says a row filter was applied.
- Defence in depth: the same rule as Postgres row-level security on the profile's DB role, with
  the warden itself setting the customer id for the transaction.
- Tests: two customers' tokens never see each other's rows through joins, subqueries, UNIONs,
  aggregates or `OR` tricks; a token without the claim is refused; integration with RLS on.

## Verification
- After each point, run `uv run ruff check . && uv run mypy && uv run pytest -m "not snowflake"`.
  Integration tests need Docker running.
- To check by hand, run `docker compose -f dev/docker-compose.yml up -d`, then
  `uv run sql-warden check/query` with good and bad SQL. Look at the per-check trace (and, from
  Phase 3 on, at `sql-warden audit tail`).
- From 2.5 on, use the portal's profile picker and Compare to check that `public` is refused
  what `admin` is allowed.
- From 1.5 on, use the portal (`uv run python -m tests.portal`); from 1.6 on, run the MCP
  server in Claude Code via `.mcp.json`. Ask the agent for something forbidden (salaries, a
  cross join, a raw SSN) and check that the refusal reason is specific and, from Phase 3 on,
  that the audit DB recorded it.
- From Phase 9 on, run `docker run` on the image with `--transport http`, point Claude Code at
  the URL with a token, and check `/readyz` and `/metrics`. Use a `public` and an `admin` token
  to confirm that their profiles differ.
