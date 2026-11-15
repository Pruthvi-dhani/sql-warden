# sql-warden reference

The detail on the topics that don't have pages of their own yet. The [docs home](index.md)
lists every page.

## The audit log

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

In production the server's audit role should be able to add records and never change or
remove one. [docs/deploy.md](deploy.md#2-the-audit-databases-roles) sets that up with
[deploy/audit_roles.sql](../deploy/audit_roles.sql), and `audit.append_only: true` makes a
server refuse to start otherwise (it warns either way, as the demo stack's superuser gets).
Three more commands are for that setup, each run as a role of its own:

```bash
sql-warden audit init --owner sql_warden_owner           # make or update the tables, as their owner
sql-warden audit prune --older-than 90d [--dry-run]      # remove old records; each prune is recorded
sql-warden audit export --since 2026-11-13 --until 2026-11-14 > day.jsonl   # JSON Lines, for analytics
```

## Sessions

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

## MCP server

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

### Over HTTP

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

### Authentication

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

### Running it as a service

The repository's `Dockerfile` builds an image of the HTTP server: two stages, so the image
holds the installed package and its dependencies but not uv or the source tree, running as
an unprivileged user of its own (uid 10001).

```bash
docker build -t sql-warden .                                  # Postgres only
docker build -t sql-warden --build-arg EXTRAS=snowflake .     # with the Snowflake engine
docker run -p 8000:8000 -v "$PWD/warden.yaml:/etc/sql-warden/warden.yaml:ro" sql-warden
```

It serves `serve --transport http --host 0.0.0.0`, so its config needs an `auth` section and
`server.allowed_hosts`. Beside `/mcp` it answers three paths that need no token, for what
runs it:

| Path       | Answers                                                                                |
|------------|----------------------------------------------------------------------------------------|
| `/healthz` | `200 ok` while the process answers at all: the liveness probe                         |
| `/readyz`  | `200` if the audit database answers and every profile's warehouse role answers and still can't write; otherwise `503` with the names of what fails (`audit`, `warehouse:public`), the reasons going to the log. Asked at most every 10 seconds |
| `/metrics` | Prometheus's text format                                                               |

| Metric                                   | What it counts                                                    |
|------------------------------------------|-------------------------------------------------------------------|
| `sql_warden_requests_total`              | requests answered, by `profile`, `kind` (query, check) and `decision` |
| `sql_warden_refusals_total`              | refusals, by `profile`, the `check` that refused, and `code`      |
| `sql_warden_request_duration_seconds`    | a histogram of how long requests took, by `profile` and `kind`    |
| `sql_warden_estimated_cost`              | a histogram of the planner's estimates, by `profile`              |
| `sql_warden_rows_returned_total`         | rows returned, by `profile`                                       |
| `sql_warden_audit_write_failures_total`  | requests answered `AUDIT_UNAVAILABLE`                             |
| `sql_warden_auth_refusals_total`         | HTTP requests turned away before reaching a profile, by `code`    |
| `sql_warden_requests_in_flight`          | requests being answered right now                                 |
| `sql_warden_config_reloads_total`        | reloads of the policy on `SIGHUP`, by `outcome` (applied, failed) |
| `sql_warden_config_last_reload_successful` | `0` while the policy file as it is now failed to load, else `1` |
| `sql_warden_pool_connections`            | connections a pool has open, by `pool` (warehouse) and `profile`  |
| `sql_warden_pool_connections_in_use`     | connections lent out right now                                    |
| `sql_warden_pool_requests_waiting`       | requests waiting for a connection, because every one is in use    |
| `sql_warden_pool_timeouts_total`         | requests that got none within `warehouse.pool.timeout_s`          |

No label holds anything a caller chooses (an identity, say), so no caller can make the set
grow. Route only `/mcp` through the public proxy: the other three are for the cluster.
[docs/deploy.md](deploy.md) has the whole of a deployment: the databases' roles,
secrets, Kubernetes and ECS, the network, and keeping the audit log.

On `SIGTERM` the server stops taking connections and gives the requests it has
`server.shutdown_grace_s` (30) seconds to finish. `server.max_concurrent_requests` (32) is how
many requests it answers at once; the rest wait.

A server keeps its connections to a Postgres warehouse in a pool, one per profile
(`warehouse.pool`: up to `max_size`, 10, each), instead of opening one for every request;
so the warehouse must allow servers × profiles × `max_size` connections. Each connection is
checked as it is lent and reset with `DISCARD ALL` as it comes back, so nothing one request
leaves on it reaches the next. A request that finds every connection in use waits up to
`timeout_s` (5) and is then answered as when the warehouse can't be reached. Snowflake keeps
one session per profile open instead. `dev/loadtest.py` measures a server under many callers
at once, against throwaway databases of its own.

### Reloading the policy

On `SIGHUP` the HTTP server reads its policy file again (`docker kill --signal HUP`, or
`kill -HUP` on its process), so keys can be revoked and issued, and profiles added or
changed, without a restart. The new policy is built in full first: the file validated, and
every profile's role looked at as at startup. Only then is it served, all at once. A request
already being answered finishes with the policy it started with, and one whose token was
checked a moment before the swap is answered by the policy that checked it. If anything
fails (a typo, a profile whose role can now write, a warehouse that can't be reached) the
server goes on with the policy it had and logs why on stderr:

```console
could not reload /etc/sql-warden/warden.yaml, so the policy loaded before is still served: /etc/sql-warden/warden.yaml: invalid config
  (top level): auth gives api key helpdesk the profile 'suport', but the config defines support
```

`sql_warden_config_last_reload_successful` stays `0` until a reload succeeds, which is
something to alert on: the file and what is served differ. Three things take a restart, and
a reload that changes them is refused: the `audit` section, the `server` section, and adding
or removing `auth`. Command-line flags still win over the file after a reload, and a server
of one profile keeps serving the one it started with. Over stdio there is no reload: the
agent that started the server restarts it.

In Kubernetes, mount the policy from a ConfigMap as a directory, not with `subPath` (a file
mounted with `subPath` is never updated), and send `SIGHUP` once the new file is in place.

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
roles first. It also compares each profile with what its role can see, since the warehouse
changes under a policy, and exits 1 if a profile names a table, column or masked column
that isn't there (dropped, renamed, or never granted):

```console
$ sql-warden config validate --live
  ...
  live:      public: role warden_public can only read
             support: role warden_reader can only read
               ! but more than the profile allows:
                 table public.employee_salaries
             admin: role warden_reader can only read
```

A table or column that is gone is refused to callers, so it is safe if not useful. A masked
column that is gone is worse: if it was renamed, a profile that allows the whole table reads
it under its new name, unmasked. A server still starts with either (a migration that drops a
column shouldn't take it down), and warns on stderr:

```console
warning: profile support masks columns its role can't see, so those masks protect nothing:
  public.customers.ssn
If a column was renamed, it is not masked under its new name: mask that one.
```

What it does not cover:

- **Grants made while it runs.** The role is looked at when the server starts and when it
  reloads; `/readyz` asks again whether it can write, at most every 10 seconds. The catalog
  is compared with the policy only at those two moments.
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
