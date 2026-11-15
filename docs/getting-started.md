# Getting started

This page takes you from a fresh clone to an agent querying the demo database through
sql-warden. It takes about ten minutes, and everything runs on your machine.

You need [uv](https://docs.astral.sh/uv/) and Docker.

## 1. Install

```bash
git clone https://github.com/Pruthvi-dhani/sql-warden && cd sql-warden
uv sync            # Python 3.12, the package and the dev tools, in .venv
```

## 2. Start the demo databases

```bash
docker compose -f dev/docker-compose.yml up -d
```

| Service     | Port | Database    | Purpose                                         |
|-------------|------|-------------|-------------------------------------------------|
| `warehouse` | 5433 | `warehouse` | the data agents query, seeded on first start    |
| `audit`     | 5434 | `audit`     | sql-warden's audit log, on a separate instance  |

The warehouse is seeded from [dev/warehouse_seed.sql](https://github.com/Pruthvi-dhani/sql-warden/blob/main/dev/warehouse_seed.sql) with
deterministic demo data:

| Table               | Rows      | Why it's there                                        |
|---------------------|-----------|-------------------------------------------------------|
| `products`          | 200       | harmless data any profile may read                    |
| `customers`         | 10,000    | has `email`, `phone` and `ssn`, to try masking on     |
| `orders`            | 1,000,000 | big enough for the cost check to mean something       |
| `employee_salaries` | 50        | meant to stay off-limits                              |

sql-warden connects as `warden_reader`, a role that can only `SELECT`. You can look at the
data directly, without sql-warden in the way:

```bash
psql postgresql://warden_reader:warden_reader@localhost:5433/warehouse
```

## 3. Pick a policy

```bash
cp warden.example.yaml warden.yaml
uv run sql-warden config validate
```

`warden.yaml` is the policy: everything sql-warden enforces comes from it. The example
defines three profiles, each a kind of caller:

| Profile            | May read                                              | Limits                              |
|--------------------|-------------------------------------------------------|-------------------------------------|
| `public` (default) | three columns of `products`                           | 50 rows a query, a small budget     |
| `support`          | `customers`, `orders`, `products`                     | `ssn`, `phone` and `email` come back masked |
| `admin`            | every table its role can read                         | 1,000 rows a query                  |

`config validate` checks the file without connecting to anything, and prints what it means.
Without a `warden.yaml`, sql-warden uses built-in settings for the demo stack, with no
profiles and so no table rules at all.

## 4. Run some queries

`check` is a dry run. It shows what each check decides, and runs nothing: the database only
plans the query, for the cost check.

```text
$ uv run sql-warden check "select id, name from products"
✓ parse   4.3 ms
✓ shape   0.1 ms
✓ access  25.4 ms
✓ cost    5.7 ms
✓ budget  0.7 ms
→ allowed (profile public; dry run, nothing was executed)
  cost: 1.02 of 10,000 allowed (most of it: Seq Scan on products)
  note: added LIMIT 51 (row cap 50 + 1 to detect truncation)
  session budget: 0 of 25 queries, 0 of 50,000 cost, 0 of 500 rows, 0 of 10 refusals used
  would run: SELECT id, name FROM public.products LIMIT 51
```

`query` runs the same checks and, if they all pass, the SQL:

```text
$ uv run sql-warden query "select id, name, price_cents from products order by id limit 5"
id | name      | price_cents
---+-----------+------------
1  | Product 1 | 637
2  | Product 2 | 774
3  | Product 3 | 911
4  | Product 4 | 1048
5  | Product 5 | 1185
(5 rows, 5 ms, profile public)
session budget: 1 of 25 queries, 0.55 of 50,000 cost, 5 of 500 rows, 0 of 10 refusals used
```

Now ask for things the policy doesn't allow. Each refusal names the check, a code and a
reason:

```text
$ uv run sql-warden check "select email from customers"
✓ parse   2.7 ms
✓ shape   0.1 ms
✗ access  TABLE_NOT_ALLOWED: table public.customers is not available to profile public
→ refused by access (profile public)
  session budget: 0 of 25 queries, 0 of 50,000 cost, 0 of 500 rows, 1 of 10 refusals used

$ uv run sql-warden check "delete from products"
✓ parse  2.6 ms
✗ shape  NOT_A_SELECT: only SELECT queries are allowed, not DELETE
→ refused by shape (profile public)
  session budget: 0 of 25 queries, 0 of 50,000 cost, 0 of 500 rows, 1 of 10 refusals used

$ uv run sql-warden check "select count(*) from orders a cross join orders b" --profile admin
✓ parse   2.8 ms
✓ shape   0.6 ms
✓ access  30.7 ms
✗ cost    COST_TOO_HIGH: the planner estimates this query at 12,847,522,946, over profile admin's limit of 1,000,000; most of it is Nested Loop. Filter on indexed columns, join on keys rather than crossing tables, or aggregate over fewer rows
→ refused by cost (profile admin)
  session budget: 1 of 50 refusals used
```

The `support` profile may read customers, but sees the sensitive columns masked:

```text
$ uv run sql-warden query "select id, phone, ssn, email from customers order by id limit 3" --profile support
id | phone       | ssn        | email
---+-------------+------------+-----------------
1  | *******7919 | [REDACTED] | d84c5e2dccdb9974
2  | *******5838 | [REDACTED] | f6ba72595cc1c3dc
3  | *******3757 | [REDACTED] | 2427ddca54b320ca
(3 rows, 19 ms, profile support)
masked: phone (partial)
masked: ssn (redact)
masked: email (hmac)
session budget: 0 of 50 refusals used
```

`tables` lists what a profile may query, which is all an agent ever learns exists:

```text
$ uv run sql-warden tables --profile support
public.customers  id, full_name, email (hmac), phone (partial), ssn (redact), country, created_at
public.orders     id, customer_id, product_id, quantity, total_cents, status, ordered_at
public.products   id, name, category, price_cents
(3 tables, profile support)
```

[The checks](checks.md) has every check and what it refuses.

## 5. Read the audit log

Every `check` and `query` is recorded in the audit database before its answer comes back,
refused or not. Yours will list what you just ran:

```text
$ uv run sql-warden audit tail -n 4
ID        TIME                 KIND   PROFILE   CLIENT            RESULT                       SQL
3f924d6f  2026-11-15 10:31:01  check  admin     cli               refused COST_TOO_HIGH        select count(*) from orders a cross join orders b
9b571177  2026-11-15 10:31:02  query  admin     cli               1 row                        select count(*) from employee_salaries
143bce47  2026-11-15 10:31:03  query  public    cli               1 row                        select id, name from products where id = 3
65857eab  2026-11-15 10:31:03  check  public    cli               refused COLUMN_NOT_ALLOWED   select category from products
```

`sql-warden audit show 65857eab` prints one record in full, and `audit tail -f` follows the
log as an agent works. More in [The audit log](audit.md).

## 6. Try the test portal

The portal is a browser page for trying queries by hand. It is a real MCP client of the same
server an agent uses, so what it shows is exactly what an agent gets back.

```bash
uv run python -m tests.portal        # opens http://127.0.0.1:8765/
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/portal-allowed-dark.png">
  <img alt="The test portal running a join: the checks pass, a LIMIT is added, and the rows are shown" src="images/portal-allowed-light.png">
</picture>

For each query it shows the verdict, one line per check, any rewrites, the exact SQL that
ran, the rows, and every JSON-RPC message in a console panel. A picker in the header switches
profile, and **Compare** shows what every profile would decide about the same query, side by
side. **Examples** has a query for each kind of refusal.

The portal only listens on 127.0.0.1. It is a testing tool, so it lives in `tests/` and is
not part of the package. More in [tests/portal/README.md](https://github.com/Pruthvi-dhani/sql-warden/blob/main/tests/portal/README.md).

## 7. Connect an agent

Claude Code can use sql-warden as a tool. It starts `sql-warden serve` itself over stdio, so
there is no port and nothing to keep running besides the demo databases. From the repo root:

```bash
claude mcp add sql-warden -- uv run --quiet --directory "$PWD" sql-warden serve --profile support
```

Or, as a project file that Claude Code asks you to approve once (it serves the default
profile, `public`):

```bash
cp .mcp.json.example .mcp.json       # git-ignored
```

Start `claude` in the repo and run `/mcp`. sql-warden should be listed as connected, with
five tools: `run_query`, `check_query`, `list_tables`, `describe_table` and `budget_status`.
Then ask in plain language and watch which tools Claude calls. As `support`:

| Ask Claude                                              | What comes back                                       |
|---------------------------------------------------------|-------------------------------------------------------|
| "What are the five best-selling products?"              | `list_tables`, then a query over `orders` and `products` |
| "Show me three customers and their SSNs"                | rows, with `ssn` as `[REDACTED]`                      |
| "Query the `employee_salaries` table"                   | refused: `TABLE_NOT_ALLOWED`                          |
| "Run `delete from orders` through sql-warden"           | refused: `NOT_A_SELECT`                               |
| "Count every pair of rows in orders with a cross join"  | refused: `COST_TOO_HIGH`                              |

A refusal comes back as a structured result with its code and reason, so Claude usually
explains it or corrects its query, instead of failing.

The server reads `./warden.yaml` from the repo, like the CLI. A policy change takes effect
when the server restarts: reconnect it from `/mcp`. Keep passwords out of the command and
out of `.mcp.json`; put them in `warden.yaml` as `${VAR}` references.

## In scripts

`check` and `query` exit with a status a script can act on:

| Exit | Meaning                                                                      |
|------|------------------------------------------------------------------------------|
| `0`  | allowed: `check` would run it, `query` ran it                                |
| `2`  | refused by a check (nothing else exits 2)                                    |
| `1`  | anything else: the database failed, it was unreachable, a bad config or flag |

`--json` prints one line of JSON instead of text, the same payload the MCP tools return:

```bash
uv run sql-warden query "select count(*) as n from orders" --profile admin --json | jq '.result.rows'
if ! uv run sql-warden check "$SQL" --json > decision.json; then jq -r .reason decision.json; fi
```

## Cleaning up

```bash
docker compose -f dev/docker-compose.yml down        # stop the demo databases, keep their data
docker compose -f dev/docker-compose.yml down -v     # and delete their data, audit log included
```

## Where next

- [How it works](how-it-works.md): what happens to a request, and why it is built this way.
- [The checks](checks.md): everything that can be refused.
- [Configuration](policy.md): writing your own policy.
- [Deploying](deploy.md): running sql-warden as a service for many agents.
