# sql-warden reference

The detail on the topics that don't have pages of their own yet. The [docs home](index.md)
lists every page.

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
