# The audit log

sql-warden records every request it answers in a separate Postgres database: who asked,
what they sent, what the checks decided, and what ran. This page covers what a record
holds, what happens when the audit database is unavailable, how to read the log, and how to
keep it in production.

The audit database is always Postgres, on its own instance, whatever the warehouse is. An
agent's queries can't reach it.

## What is recorded

Every `check` and `query`, from the CLI or an agent, is recorded in the audit database before
anything comes back: allowed, refused, failed or timed out, with the SQL as sent and as run,
the profile, the client, the full trace, and how many rows came back.

Two things are not kept exactly as sent: a query too long to be read is recorded as its
first 2,000 characters and its length, and characters Postgres can't store as text are
written as escapes.

The result's `audit_id` (in `--json` and the MCP results) is the record's id. On Snowflake,
each query's `QUERY_TAG` carries it too, so Snowflake's query history and the audit log can
be matched record for record.

## It fails closed

sql-warden won't start without its audit database. If the audit database goes away later, allowed queries are refused with `AUDIT_UNAVAILABLE` before they reach the warehouse. If a
record can't be written after a query ran, its rows are withheld. Nothing is answered
without a record.

## Reading it

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
uv run sql-warden audit tail --identity support-bot      # everything one caller asked: an API key's name, or oidc:<subject>
```

## In production

In production the server's audit role should be able to add records and never change or
remove one. [Deploying](deploy.md#2-the-audit-databases-roles) sets that up with
[deploy/audit_roles.sql](../deploy/audit_roles.sql), and `audit.append_only: true` makes a
server refuse to start otherwise (it warns either way, as the demo stack's superuser gets).
Three more commands are for that setup, each run as a role of its own:

```bash
sql-warden audit init --owner sql_warden_owner           # make or update the tables, as their owner
sql-warden audit prune --older-than 90d [--dry-run]      # remove old records; each prune is recorded
sql-warden audit export --since 2026-11-13 --until 2026-11-14 > day.jsonl   # JSON Lines, for analytics
```

## Where next

- [Deploying](deploy.md#2-the-audit-databases-roles): the audit roles, retention and export
  in a real deployment.
- [Sessions and budgets](budgets.md): budgets are kept in the audit database too.
