# The policy file

Everything sql-warden enforces comes from one file, `warden.yaml`. This page covers where
the policy is read from, what its sections are, how profiles work, and how to check a policy
before you serve it. [warden.example.yaml](../warden.example.yaml) is a complete policy with
a comment on every key.

## Starting one

```bash
cp warden.example.yaml warden.yaml
uv run sql-warden config validate          # checks the file without connecting
uv run sql-warden config validate --live   # then connects as each profile's role and checks it
```

`warden.yaml` is git-ignored, so a local policy never ends up in a commit.

## Where the policy comes from

Highest priority first:

1. command-line flags (`--dsn`, `--max-rows`, `--timeout-ms`, `--profile`, `--audit-dsn`) and
   the environment variables `SQL_WARDEN_DSN`, `SQL_WARDEN_PROFILE` and `SQL_WARDEN_AUDIT_DSN`
2. the file given by `--config PATH` or `SQL_WARDEN_CONFIG`
3. `./warden.yaml`, if it exists
4. built-in defaults for the local demo stack

A profile's own settings are the exception to the first line: a flag can't widen what a
profile reads. See [Profiles](#profiles).

## Secrets

A value can reference an environment variable as `${NAME}`, or `${NAME:-default}` to fall
back when it isn't set. Use this for every password and key, so none is written in the file:

```yaml
warehouse:
  dsn: postgresql://warden_reader:${WARDEN_READER_PASSWORD}@db.internal/warehouse
```

`config validate` never prints a password.

## The sections

Unknown keys are errors, so a typo is caught instead of silently ignored. Every section is
optional except `version`.

| Section            | What it sets                                                         | More                                              |
|--------------------|----------------------------------------------------------------------|---------------------------------------------------|
| `version`          | the file format: `1`                                                 |                                                   |
| `warehouse`        | the database agents query: engine, connection, timeout, row cap, pool | [below](#warehouse)                              |
| `shape`            | structural rules: joins, nesting, the LIMIT policy, function and type lists | [below](#shape), [the shape check](checks.md#shape) |
| `cost`             | the most a query may cost, by the planner's estimate                 | [below](#cost), [the cost check](checks.md#cost)  |
| `budgets`          | what one session may use in total                                    | [Session budgets](reference.md#session-budgets)   |
| `identity_budgets` | what one caller with a token may use over a rolling window           | [Budgets per caller](reference.md#budgets-per-caller) |
| `masking`          | the key for `hmac` masks                                             | [Masked columns](masking.md)     |
| `audit`            | the audit database                                                   | [below](#audit), [The audit log](reference.md#the-audit-log) |
| `server`           | where the HTTP server listens, and its limits                        | [below](#server), [Over HTTP](reference.md#over-http) |
| `auth`             | API keys and OIDC tokens for HTTP callers                            | [Authentication](reference.md#authentication)     |
| `profiles`, `default_profile` | the rules for each kind of caller                         | [Profiles](#profiles)                             |

### warehouse

| Key                    | Default      | Meaning                                                            |
|------------------------|--------------|--------------------------------------------------------------------|
| `engine`               | `postgres`   | `postgres` or `snowflake`                                          |
| `dsn`                  | the demo stack's | the connection string, for profiles without one of their own   |
| `statement_timeout_ms` | `5000`       | a query running longer is cancelled                                |
| `max_rows`             | `100`        | the row cap: more rows are cut off, and the result says so         |
| `connect_timeout_s`    | `5`          | how long to wait for a connection                                  |
| `pool.max_size`        | `10`         | connections a server keeps open, per profile. Postgres only        |
| `pool.max_idle_s`      | `300`        | an idle connection is closed after this                            |
| `pool.max_lifetime_s`  | `1800`       | any connection is replaced after this                              |
| `pool.timeout_s`       | `5`          | how long a request waits when every connection is in use           |

### shape

| Key                  | Default  | Meaning                                                                |
|----------------------|----------|------------------------------------------------------------------------|
| `max_joins`          | `4`      | joins per query, comma joins included                                  |
| `max_subquery_depth` | `3`      | how deep subqueries and CTEs may nest                                  |
| `limit`              | `inject` | `inject` adds or lowers a `LIMIT`; `require` refuses the query instead |
| `allowed_functions`  | `[]`     | non-standard functions to allow, such as `[age, pg_typeof]`            |
| `denied_functions`   | `[]`     | more names or glob patterns to refuse, such as `[md5, "regexp_*"]`     |
| `allowed_types`      | `[]`     | non-standard types a query may cast to, such as `[order_status]`       |

### cost

| Key              | Default   | Meaning                                                                   |
|------------------|-----------|---------------------------------------------------------------------------|
| `max_total_cost` | `1000000` | a query estimated above this is refused. On Snowflake the unit is bytes, and the default is 10 GiB |

### audit

| Key                 | Default          | Meaning                                                           |
|---------------------|------------------|-------------------------------------------------------------------|
| `dsn`               | the demo stack's | the audit database: always Postgres, on its own instance          |
| `connect_timeout_s` | `5`              | how long to wait for a connection                                 |
| `append_only`       | `false`          | `true`: refuse to serve unless the role can only add records      |

### server

| Key                       | Default     | Meaning                                                          |
|---------------------------|-------------|------------------------------------------------------------------|
| `host`                    | `127.0.0.1` | the address the HTTP server listens on. Beyond loopback needs `auth` |
| `port`                    | `8000`      |                                                                  |
| `allowed_hosts`           | `[]`        | the names clients reach the server by, when it listens beyond loopback |
| `allowed_origins`         | `[]`        | web pages that may call it from a browser                        |
| `max_concurrent_requests` | `32`        | requests answered at once; more wait                             |
| `shutdown_grace_s`        | `30`        | on `SIGTERM`, how long requests in progress get to finish        |

## Profiles

A profile is who a server serves: say `public` for an agent released to customers, and `admin`
for internal admins. Each server is tied to one profile when it starts, and nothing an agent
sends can change it (the tools take only SQL). Over HTTP with
[authentication](reference.md#authentication), one server serves every profile, and each
caller's token decides which they get.

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
cp warden.example.yaml warden.yaml                                                   # ships public, support and admin
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

### What a caller can see

`list_tables`, `describe_table` and `sql-warden tables` show only what the profile may query,
so an agent never learns that the other tables exist. Each table says `all_columns`: whether
`SELECT *` works on it.

```bash
uv run sql-warden tables                     # public.products  id, name, price_cents  (some columns)
uv run sql-warden tables products --json     # the same payload describe_table returns
```

### Let the database enforce it too

Give a profile its own `dsn` as a role with matching grants, and Postgres enforces the same
rules underneath (the demo's `warden_public` can read only those three product columns). The
access check reads the catalog to resolve names, so with profiles even `check` connects to the
database (to read the catalog, never to run the query); if it can't, the query is refused with
`CATALOG_UNAVAILABLE`. Without a `profiles` section there is one implicit profile, `all`, with
no table rules, and `config validate` says so.

## Checking a policy

`config validate` reads the file, reports every problem at once with its location, and
prints what the policy means:

```text
$ uv run sql-warden config validate
✓ warden.yaml is valid
  warehouse: postgres at localhost:5433/warehouse as warden_reader
             statement timeout 5000 ms, max 100 rows
  audit:     postgres at localhost:5434/audit as warden_audit
  shape:     up to 4 joins, subqueries up to 3 deep
             LIMIT added or lowered to the row cap
  cost:      refused above an estimated 1,000,000
  budgets:   per session: 50 refusals
  server:    http on 127.0.0.1:8000, this machine only
  auth:      none: HTTP needs no token, and is served on loopback only
  masking:   hmac key set
  profiles:  public (default): connects to localhost:5433/warehouse as warden_public
               reads public.products (id, name, price_cents)
               max 50 rows
               refused above an estimated 10,000
               budget per session: 25 queries, cost 50,000, 500 rows, 10 refusals
             support: connects with warehouse.dsn
               reads public.customers (every column)
               reads public.orders (every column)
               reads public.products (every column)
               masks public.customers.ssn (redact)
               masks public.customers.phone (partial)
               masks public.customers.email (hmac)
             admin: connects with warehouse.dsn
               reads every table its role can
               max 1000 rows
```

It connects to nothing, so it is safe in CI. With `--live` it then connects to the warehouse
as each profile's role, as a server does before it starts, and exits 1 if:

- a role can write, or can't be checked, or
- a profile names a table, column or masked column its role can't see: dropped, renamed, or
  never granted.

Run it in a deploy pipeline to check a policy against the real roles before it is served.
[Defence in depth](reference.md#defence-in-depth) explains what it looks for.

## Changing a policy

Over stdio, a policy change takes effect when the server restarts. An HTTP server reads its
policy again on `SIGHUP`, and serves the new one only if all of it loads. See
[Reloading the policy](reference.md#reloading-the-policy).
