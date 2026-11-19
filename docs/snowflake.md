# Snowflake

The warehouse behind sql-warden can be Snowflake instead of Postgres. The checks, the
policy file, masking, budgets and the audit log all work the same way. The audit database
stays Postgres either way. This page covers the setup, what differs from Postgres, and how
far the Snowflake engine has been tested.

> **Only the engine's live tests have run against a real account.** A server has not yet
> been run on one. See [How far it is tested](#how-far-it-is-tested) before relying on it.

## Setting it up

Install the connector, which is an optional extra, and name the engine in `warden.yaml`:

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

## The connection string

The connection string is `snowflake://USER:PASSWORD@ACCOUNT/DATABASE/SCHEMA`, with
`warehouse`, `role`, `authenticator`, `private_key_file` and `private_key_file_pwd` as
options after `?`. A password or programmatic access token goes in the password's place; for
a key pair, leave it out and give `private_key_file`. Characters a URL can't hold are
percent-encoded. A profile's own `dsn` works as for Postgres: usually another role.

## What is different from Postgres

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
  [looks at it before it starts](defence-in-depth.md): it doesn't serve as a role that holds
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

## How far it is tested

The engine is tested against a stand-in for the connector (every `pytest`), and on
[fakesnow](https://github.com/tekumara/fakesnow), which runs Snowflake SQL on DuckDB. fakesnow
has no planner, so the cost check is tested on saved plans, one from Snowflake's documentation
and the rest written in its shape. The live tests have also passed against a real trial
account. They connect, run a query, keep to the row cap and the statement timeout, explain,
read the catalog, refuse a second statement and report the role, and they only read. **A
server has not yet been run on a real account.**

```bash
uv run --with 'fakesnow==0.12.1' --with 'snowflake-connector-python<5' pytest tests/fakesnow
SNOWFLAKE_DSN='snowflake://...' uv run pytest -m snowflake
```

The first runs the emulator suite, and the second runs the live suite against your account.
fakesnow is kept out of the project's own dependencies because it pins the SQL parser to an
older release and needs a connector before version 5; the first command lays it over the
environment for that run only.

## Where next

- [The shape check on Snowflake](checks.md#on-snowflake): the Snowflake-specific functions
  and syntax it refuses.
- [The policy file](policy.md): the rest of the policy, which is the same on both engines.
