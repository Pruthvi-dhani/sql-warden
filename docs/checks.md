# The checks

Every query goes through the checks below, in this order. The first one that fails refuses
the query, with a code and a reason, and the rest don't run. [How it works](how-it-works.md)
has the whole path a request takes; this page says what each check refuses.

| Check                 | Runs for                          | Refuses with                                     |
|-----------------------|-----------------------------------|--------------------------------------------------|
| [parse](#parse)       | every query                       | `PARSE_ERROR`, `QUERY_TOO_COMPLEX`               |
| [shape](#shape)       | every query                       | `MULTIPLE_STATEMENTS`, `NOT_A_SELECT`, `NOT_READ_ONLY`, `FUNCTION_NOT_ALLOWED`, `TYPE_NOT_ALLOWED`, `TOO_MANY_JOINS`, `SUBQUERY_TOO_DEEP`, `INVALID_LIMIT`, `LIMIT_REQUIRED`, `LIMIT_TOO_HIGH` |
| [access](#access)     | a profile with table rules        | `TABLE_NOT_ALLOWED`, `COLUMN_NOT_ALLOWED`, `STAR_NOT_ALLOWED`, `CATALOG_UNAVAILABLE` |
| [masking](#masking)   | a profile with masked columns     | `MASKED_COLUMN_IN_PREDICATE`, `MASKED_COLUMN_IN_EXPRESSION` |
| [cost](#cost)         | every query                       | `COST_TOO_HIGH`, `PLAN_FAILED`, `COST_UNAVAILABLE` |
| [budget](#budget)     | a profile with a budget           | `BUDGET_EXHAUSTED`, `COST_OVER_BUDGET`, `BUDGET_UNAVAILABLE` |

The examples use the demo data and the profiles in `warden.example.yaml`. To try them, see
[Getting started](getting-started.md).

## Parse

The SQL must parse. A syntax error is refused with `PARSE_ERROR`, and the reason gives the
line and column:

```text
$ uv run sql-warden check "select (1"
✗ parse  PARSE_ERROR: Expecting ) (line 1, col 9)
→ refused by parse (profile public)
  session budget: 0 of 25 queries, 0 of 50,000 cost, 0 of 500 rows, 1 of 10 refusals used
```

Before that, the query must be safe to read at all. The parser backtracks when it guesses
wrong, and a query built to exploit that (`date(date(date(...` thirty levels deep) could
keep it busy for hours. So a query is turned away unread, with `QUERY_TOO_COMPLEX`, if it:

- is longer than 20,000 characters,
- nests brackets more than 32 deep, or
- nests more than 4 type names followed by a bracket (`date(`, `array[`).

## Shape

The query must be one read-only `SELECT`, within the structural rules in the policy's
`shape` section.

| Try                                                           | Refused with           |
|---------------------------------------------------------------|------------------------|
| `select 1; select 2`                                          | `MULTIPLE_STATEMENTS`  |
| `delete from orders`, `drop table orders`, `do $$ ... $$`     | `NOT_A_SELECT`         |
| `with x as (delete from orders returning *) select * from x`  | `NOT_READ_ONLY`        |
| `select * into copy from customers`, `... for update`         | `NOT_READ_ONLY`        |
| `select pg_sleep(60)`, `pg_read_file(...)`, `dblink(...)`     | `FUNCTION_NOT_ALLOWED` |
| `select age(created_at) from customers` (unknown function)    | `FUNCTION_NOT_ALLOWED` |
| `select 'secrets'::regclass`, `select (null::secrets).*`      | `TYPE_NOT_ALLOWED`     |
| more than `max_joins` joins (4 by default)                    | `TOO_MANY_JOINS`       |
| subqueries or CTEs nested deeper than `max_subquery_depth` (3 by default) | `SUBQUERY_TOO_DEEP` |
| `select 1 limit all`                                          | `INVALID_LIMIT`        |

### Functions

A function sqlglot doesn't recognise as standard SQL is refused unless it is listed in
`shape.allowed_functions`. Some are dangerous enough to be refused even if listed:
`pg_sleep*`, `pg_read_file`, `lo_*`, `dblink*`, `set_config`, `query_to_xml` and others.
`shape.denied_functions` adds names or glob patterns of your own.

### Types

Casts work the same way. In Postgres every table is also a type, and some types look a name
up in the catalog. So `'secrets'::regclass` or `(null::secrets).*` would tell a caller which
tables exist and what their columns are called, whatever its profile may read.

A cast to a type that isn't standard SQL is refused unless the type is listed in
`shape.allowed_types` (for an enum, a domain or an extension's type). `regclass`, `regrole`
and the rest of that family are refused even if listed.

### LIMIT

With `shape.limit: inject`, the default, a query without a `LIMIT` gets one, and a `LIMIT`
above the row cap is lowered. The new limit is the row cap plus one, so the result can still
say whether it was cut off. The response lists the change under `rewrites`:

```text
  note: added LIMIT 51 (row cap 50 + 1 to detect truncation)
  would run: SELECT id, name FROM public.products LIMIT 51
```

With `shape.limit: require`, such queries are refused instead, with `LIMIT_REQUIRED` or
`LIMIT_TOO_HIGH`. Either way, a limit sql-warden can't enforce (`LIMIT ALL`, an expression,
`FETCH ... WITH TIES`) is refused with `INVALID_LIMIT`.

### On Snowflake

The checks read a query in its warehouse's dialect, and each dialect has its own list of
dangerous functions. Snowflake's includes `system$*`, `result_scan`, `get_ddl` and
`query_history*`.

Read as Snowflake, a query must also name outright everything it reads. These are refused
even where no profile limits tables:

| Try                                                   | Refused with           |
|-------------------------------------------------------|------------------------|
| `select * from identifier('secrets')`, `table('secrets')`, `table($t)` | `FUNCTION_NOT_ALLOWED` |
| `select $1 from @my_stage/file.csv` (a stage's files)  | `TABLE_NOT_ALLOWED`    |
| `select $3 from products` (a column by position), `$variable` | `COLUMN_NOT_ALLOWED` |
| `select my_sequence.nextval`                           | `NOT_READ_ONLY`        |

`select top 5000 ...` is a limit like any other, and is lowered to the row cap.

## Access

A query may use only the tables and columns its [profile](reference.md#profiles) allows.
That holds wherever the query uses them: selected, filtered, joined, grouped or sorted on,
in subqueries and in CTEs. With the example's `public` profile, which may read three columns
of `products`:

| Try                                                           | Refused with           |
|---------------------------------------------------------------|------------------------|
| `select count(*) from employee_salaries`                      | `TABLE_NOT_ALLOWED`    |
| `select 1 from nosuch`                                        | `TABLE_NOT_ALLOWED`    |
| `select 1 from information_schema.tables`                     | `TABLE_NOT_ALLOWED`    |
| `select category from products`                               | `COLUMN_NOT_ALLOWED`   |
| `select id from products order by category`                   | `COLUMN_NOT_ALLOWED`   |
| `select * from products`, `select row_to_json(p) from products p` | `STAR_NOT_ALLOWED`, listing the allowed columns |

```text
$ uv run sql-warden check "select email from customers"
✓ parse   2.7 ms
✓ shape   0.1 ms
✗ access  TABLE_NOT_ALLOWED: table public.customers is not available to profile public
→ refused by access (profile public)
  session budget: 0 of 25 queries, 0 of 50,000 cost, 0 of 500 rows, 1 of 10 refusals used
```

Three things to know:

- **A caller can't probe for names.** A table that doesn't exist gets the same answer as one
  the profile may not read, and so does a column.
- **The database reads the table that was checked.** An allowed query runs with each table
  pinned to its schema (`products` becomes `public.products`).
- **The check needs the catalog.** It reads the warehouse's tables and columns to resolve
  names, and caches them. If it can't, the query is refused with `CATALOG_UNAVAILABLE`.

Without a `profiles` section there is one implicit profile, `all`, with no table rules and
no access check.

## Masking

A profile can see a column [masked](reference.md#masked-columns). A masked column may only
be selected as it is, in which case its values come back masked, or counted. Anything else
could reveal what the mask hides. With the example's `support` profile, which sees `ssn`,
`phone` and `email` masked:

| Try                                                           | Result                        |
|---------------------------------------------------------------|-------------------------------|
| `select id, ssn from customers`                               | allowed, `ssn` as `[REDACTED]` |
| `select count(distinct ssn) from customers`                   | allowed                       |
| `select id from customers where ssn like '123%'`              | `MASKED_COLUMN_IN_PREDICATE`  |
| `... join ... on c.email = ...`, `group by email`, `order by phone`, `distinct ssn` | `MASKED_COLUMN_IN_PREDICATE` |
| `select upper(email)`, `split_part(email, '@', 2)`, `max(ssn)` | `MASKED_COLUMN_IN_EXPRESSION` |

```text
$ uv run sql-warden check "select id from customers where ssn like '123%'" --profile support
✓ parse    3.0 ms
✓ shape    0.1 ms
✓ access   31.7 ms
✗ masking  MASKED_COLUMN_IN_PREDICATE: column ssn of public.customers is masked for profile support, so the query can't use it in WHERE: filtering, joining, grouping or sorting on it would reveal what the mask hides. Select it on its own, or leave it out
→ refused by masking (profile support)
  session budget: 1 of 50 refusals used
```

The filter is refused because of what it would leak: a caller could ask
`where ssn like '1%'`, then `'12%'`, and read the value one digit at a time from which rows
come back.

The column is followed through aliases, CTEs, subqueries and unions, so renaming it changes
nothing.

## Cost

The database's own planner estimates what the query would cost, and a query estimated above
`cost.max_total_cost` is refused before it runs. The default limit is 1,000,000, and a
profile can set its own.

The estimate comes from `EXPLAIN`, which plans a query without running it. sql-warden never
uses `EXPLAIN ANALYZE`, which would run it. On the demo data:

| Try                                                           | Estimate        | Result                  |
|---------------------------------------------------------------|-----------------|-------------------------|
| `select * from orders where id = 42`                          | about 8         | allowed                 |
| `select sum(quantity) from orders` (a full scan)              | about 15,000    | allowed                 |
| `select count(*) from orders a cross join orders b`           | about 10^10     | `COST_TOO_HIGH`         |
| `select 1 / 0`                                                | none: Postgres fails it while planning | `PLAN_FAILED` |

```text
$ uv run sql-warden check "select count(*) from orders a cross join orders b" --profile admin
✓ parse   2.8 ms
✓ shape   0.6 ms
✓ access  30.7 ms
✗ cost    COST_TOO_HIGH: the planner estimates this query at 12,847,522,946, over profile admin's limit of 1,000,000; most of it is Nested Loop. Filter on indexed columns, join on keys rather than crossing tables, or aggregate over fewer rows
→ refused by cost (profile admin)
  session budget: 1 of 50 refusals used
```

Three things to know:

- **The unit is the planner's.** On Postgres it is the planner's cost units. On Snowflake it
  is the bytes the query may scan, and the default limit is 10 GiB.
- **A `LIMIT` is priced in.** `select * from orders a cross join orders b` with the added
  `LIMIT 101` stops after 101 rows, and the planner knows it: the estimate is about 2.
- **An unknown cost doesn't run.** If the database can't be reached to plan the query, it is
  refused with `COST_UNAVAILABLE`.

Postgres finds many errors while planning, such as a column that doesn't exist. Those come
back as `PLAN_FAILED`, with the database's message pointing into the SQL that would have
run. Here without a policy file, so the profile is `all`:

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

An error found only while running, such as a division by zero on some row, is not a refusal.
It is reported as the database gave it, and the CLI exits 1.

## Budget

A profile can cap what one session may use in total: queries, their estimated cost, rows
returned, and refusals. The budget is checked in two places.

- **Before every other check.** A session that has already reached a limit is refused with
  `BUDGET_EXHAUSTED`. Its query isn't even parsed, so it learns nothing more, and the
  database isn't asked to plan anything.
- **After the cost check.** A query whose estimated cost is more than the session has left
  is refused with `COST_OVER_BUDGET`. A cheaper query may still fit.

The limit on refusals is what stops an agent from trying query after query until one gets
through. If the session's usage can't be read, the query is refused with
`BUDGET_UNAVAILABLE`.

A caller with a token can also have a budget of their own over a rolling window, across all
their sessions. Both budgets are checked in one step, and the refusal says which ran out.
[Session budgets](reference.md#session-budgets) has how each limit is counted.

## Every refusal code

| Code                          | From    | Meaning                                                              |
|-------------------------------|---------|----------------------------------------------------------------------|
| `PARSE_ERROR`                 | parse   | the SQL has a syntax error                                           |
| `QUERY_TOO_COMPLEX`           | parse   | too long or too deeply nested to be read safely                      |
| `MULTIPLE_STATEMENTS`         | shape   | more than one statement                                              |
| `NOT_A_SELECT`                | shape   | anything but a `SELECT`, a `UNION` of them, or a CTE query           |
| `NOT_READ_ONLY`               | shape   | a `SELECT` that writes or locks: a data-modifying CTE, `SELECT INTO`, `FOR UPDATE` |
| `FUNCTION_NOT_ALLOWED`        | shape   | a function that is denied, or unknown and not allowlisted            |
| `TYPE_NOT_ALLOWED`            | shape   | a cast to a type that isn't standard SQL and not allowlisted         |
| `TOO_MANY_JOINS`              | shape   | more joins than `shape.max_joins`                                    |
| `SUBQUERY_TOO_DEEP`           | shape   | nesting deeper than `shape.max_subquery_depth`                       |
| `INVALID_LIMIT`               | shape   | a limit that can't be enforced, such as `LIMIT ALL`                  |
| `LIMIT_REQUIRED`              | shape   | no `LIMIT`, under `shape.limit: require`                             |
| `LIMIT_TOO_HIGH`              | shape   | a `LIMIT` above the row cap, under `shape.limit: require`            |
| `TABLE_NOT_ALLOWED`           | access  | a table the profile may not read, or that doesn't exist              |
| `COLUMN_NOT_ALLOWED`          | access  | a column the profile may not read, or that doesn't exist             |
| `STAR_NOT_ALLOWED`            | access  | `*` or a whole-row reference on a table the profile reads only some columns of |
| `CATALOG_UNAVAILABLE`         | access  | the tables and columns couldn't be read, so access couldn't be checked |
| `MASKED_COLUMN_IN_PREDICATE`  | masking | a masked column used to filter, join, group, sort or compare rows    |
| `MASKED_COLUMN_IN_EXPRESSION` | masking | a masked column inside an expression                                 |
| `COST_TOO_HIGH`               | cost    | the planner's estimate is over the profile's limit                   |
| `PLAN_FAILED`                 | cost    | the database rejected the query while planning it                    |
| `COST_UNAVAILABLE`            | cost    | the database couldn't be reached to plan the query                   |
| `BUDGET_EXHAUSTED`            | budget  | the session or caller has reached a limit                            |
| `COST_OVER_BUDGET`            | budget  | the query costs more than the session or caller has left             |
| `BUDGET_UNAVAILABLE`          | budget  | usage couldn't be read, so the budget couldn't be checked            |
| `AUDIT_UNAVAILABLE`           | server  | the request couldn't be recorded, so nothing is returned             |
| `INTERNAL_ERROR`              | server  | a check crashed; the query is refused, not let through               |
| `UNAUTHENTICATED`             | HTTP    | no token, or one that isn't valid; answered `401`                    |
| `NO_PROFILE`                  | HTTP    | a valid token that gives no profile this server has; answered `403`  |
| `AUTH_UNAVAILABLE`            | HTTP    | the identity provider's keys couldn't be fetched; answered `503`     |

The three HTTP codes come before any check: the request is turned away unread. See
[Authentication](reference.md#authentication).

### Which are worth retrying

The codes ending in `_UNAVAILABLE` mean sql-warden or a database behind it had trouble, and
the same query may work later. Every other code is about the query or the caller's budget:
sending the same query again gets the same answer.

### Which count against a budget

A refusal counts towards a session's `max_refusals` unless it is the budget's own
(`BUDGET_EXHAUSTED`, `COST_OVER_BUDGET`) or not the caller's doing (`COST_UNAVAILABLE`,
`CATALOG_UNAVAILABLE`, `BUDGET_UNAVAILABLE`, `AUDIT_UNAVAILABLE`, `INTERNAL_ERROR`). A dry
run that is refused counts like any other.
