# Command reference

Every `sql-warden` command, its options and its exit codes. In a clone of the repository,
run it as `uv run sql-warden`. `sql-warden COMMAND --help` prints the same information.

```text
sql-warden [--config FILE] COMMAND [OPTIONS]
```

| Command                             | What it does                                                    |
|-------------------------------------|-----------------------------------------------------------------|
| [`query`](#query-and-check)         | runs SQL through the checks and, if allowed, against the warehouse |
| [`check`](#query-and-check)         | dry run: shows what each check decides, and runs nothing        |
| [`tables`](#tables)                 | lists the tables the profile may query, or describes one        |
| [`serve`](#serve)                   | serves the MCP tools, over stdio or HTTP                        |
| [`config validate`](#config-validate) | checks a policy file                                          |
| [`audit tail`](#audit-tail)         | prints the most recent audit events                             |
| [`audit show`](#audit-show)         | prints everything recorded about one request                    |
| [`audit init`](#audit-init)         | creates or updates the audit tables                             |
| [`audit prune`](#audit-prune)       | removes old audit records                                       |
| [`audit export`](#audit-export)     | writes a window of audit events as JSON Lines                   |
| [`auth new-key`](#auth-new-key)     | makes an API key for an HTTP caller                             |

## Global options

| Option          | Meaning                                                                        |
|-----------------|--------------------------------------------------------------------------------|
| `--config FILE` | the policy file. Without it: `SQL_WARDEN_CONFIG`, then `./warden.yaml`, then built-in settings for the demo stack |
| `--version`     | prints the version                                                             |

`--config` goes before the command: `sql-warden --config prod.yaml check "..."`.

## Connection options

`query`, `check`, `tables` and `serve` share these. Each overrides the policy file, except
where a profile sets its own value: a flag can't widen what a profile reads.

| Option            | Environment variable   | Overrides                                                  |
|-------------------|------------------------|------------------------------------------------------------|
| `--dsn TEXT`      | `SQL_WARDEN_DSN`       | `warehouse.dsn`, which profiles without their own `dsn` use |
| `--max-rows N`    |                        | `warehouse.max_rows`, but not a profile's own `max_rows`   |
| `--timeout-ms N`  |                        | `warehouse.statement_timeout_ms`                           |
| `--profile TEXT`  | `SQL_WARDEN_PROFILE`   | `default_profile`. An unknown name is an error             |
| `--audit-dsn TEXT` | `SQL_WARDEN_AUDIT_DSN` | `audit.dsn`. The `audit` commands take this one too       |

## query and check

```text
sql-warden query [OPTIONS] SQL
sql-warden check [OPTIONS] SQL
```

`check` runs the checks and executes nothing: the database only plans the query, for the
cost check. `query` runs the same checks and, if they all pass, the SQL. Both are recorded
in the audit log.

| Option           | Meaning                                                                       |
|------------------|-------------------------------------------------------------------------------|
| `--session NAME` | the session this call belongs to. Calls given the same name share one session, and one budget. Without it, each call is a session of its own |
| `--json`         | prints the decision as one line of JSON: the payload the MCP tools return     |

| Exit | Meaning                                                                      |
|------|------------------------------------------------------------------------------|
| `0`  | allowed: `check` would run it, `query` ran it                                |
| `2`  | refused by a check (nothing else exits 2)                                    |
| `1`  | anything else: the database failed, it was unreachable, a bad config or flag |

```bash
sql-warden check "select id, name from products"
sql-warden query "select count(*) from orders" --profile admin --json | jq '.result.rows'
sql-warden query "select id from products limit 3" --session nightly-2026-11-15
```

## tables

```text
sql-warden tables [OPTIONS] [NAME]
```

Lists the tables and columns the profile may query, with masked columns marked. With a
table name it describes that one. `--json` prints the payload the `list_tables` and
`describe_table` tools return.

```text
$ sql-warden tables --profile support
public.customers  id, full_name, email (hmac), phone (partial), ssn (redact), country, created_at
public.orders     id, customer_id, product_id, quantity, total_cents, status, ordered_at
public.products   id, name, category, price_cents
(3 tables, profile support)
```

## serve

```text
sql-warden serve [OPTIONS]
```

Serves the MCP tools. Before it serves anything it asks the warehouse what each profile's
role can do, and doesn't start as one that can write.

| Option                | Meaning                                                                  |
|-----------------------|--------------------------------------------------------------------------|
| `--transport stdio`   | the default: for an agent that starts sql-warden itself. Serves one profile |
| `--transport http`    | Streamable HTTP at `/mcp`. Without an `auth` section it serves one profile; with one it serves them all, and each request's token decides which |
| `--host TEXT`         | HTTP only: the address to listen on; overrides `server.host`. Loopback only unless the policy has an `auth` section |
| `--port N`            | HTTP only; overrides `server.port` (8000)                                |

Over HTTP, `SIGHUP` reloads the policy file, and `SIGTERM` shuts the server down after giving
the requests in progress time to finish. See [The MCP server](mcp-server.md) and
[Operating a server](operations.md).

## config validate

```text
sql-warden config validate [--live] [PATH]
```

Checks a policy file without connecting to anything, reports every problem at once, and
prints what the policy means. The file is `PATH`, else `--config`, else `./warden.yaml`.

With `--live` it then connects to the warehouse as each profile's role, as a server does
before it starts.

| Exit | Meaning                                                                         |
|------|---------------------------------------------------------------------------------|
| `0`  | the file is valid and, with `--live`, every role passed                         |
| `1`  | the file is invalid; or, with `--live`, a role can write or couldn't be checked, or a profile names a table, column or masked column its role can't see |

See [Checking a policy](policy.md#checking-a-policy).

## audit tail

```text
sql-warden audit tail [OPTIONS]
```

Prints the most recent events, oldest first.

| Option                               | Meaning                                                  |
|--------------------------------------|----------------------------------------------------------|
| `-n`, `--lines N`                    | how many events (20 by default, up to 10,000)            |
| `--profile TEXT`                     | only events for this profile                             |
| `--session TEXT`                     | only events of this session: a response's `session_id`, or a `--session` name |
| `--identity TEXT`                    | only events of this caller: an API key's name, or `oidc:<subject>` |
| `--decision allowed\|refused\|failed` | only events with this outcome                           |
| `-f`, `--follow`                     | keeps printing events as they are recorded, until Ctrl+C |
| `--json`                             | one JSON object per event, one per line                  |

## audit show

```text
sql-warden audit show [--json] EVENT_ID
```

Prints everything recorded about one request. `EVENT_ID` is the request's `audit_id`, or the
first few characters of it.

## audit init

```text
sql-warden audit init [--owner ROLE]
```

Creates or updates the audit tables, and grants the roles from
[deploy/audit_roles.sql](https://github.com/Pruthvi-dhani/sql-warden/blob/main/deploy/audit_roles.sql) what each may do. A server whose role
owns the tables does this itself as it starts. A server whose role may only add records
can't, so the tables' owner runs this first, and again after an upgrade.

`--owner ROLE` makes the tables as that role, which then owns them. The connecting role
must be a member of it.

## audit prune

```text
sql-warden audit prune --older-than AGE [--dry-run]
```

Removes events recorded before the cutoff, the budgets of sessions idle since then, and
callers' charges older than any budget's window. Each prune is itself recorded, in the same
transaction.

| Option             | Meaning                                                              |
|--------------------|----------------------------------------------------------------------|
| `--older-than AGE` | required. Days or hours, such as `90d` or `36h`; at least `1d`       |
| `--dry-run`        | counts what would be removed, and removes nothing                    |

Run it on a schedule, as a role that may prune and not as the server's role.

## audit export

```text
sql-warden audit export --since TIMESTAMP [--until TIMESTAMP] [-o FILE]
```

Writes every event recorded in a window, oldest first, one JSON object per line, in the
format `audit tail --json` prints. It only reads, so a read-only role is enough.

| Option              | Meaning                                                             |
|---------------------|---------------------------------------------------------------------|
| `--since TIMESTAMP` | required. From this time, included                                  |
| `--until TIMESTAMP` | up to this time, not included. By default a minute ago, so the window is closed |
| `-o`, `--output FILE` | writes to a file instead of stdout                                |

Windows that meet export every event exactly once, so a scheduled export can start each run
where the last one ended:

```bash
sql-warden audit export --since 2026-11-13 --until 2026-11-14 > day.jsonl
```

The roles for `init`, `prune` and `export` are set up in
[Deploying](deploy.md#2-the-audit-databases-roles).

## auth new-key

```text
sql-warden auth new-key NAME --profile PROFILE
```

Makes an API key for `NAME`, who will hold it, and prints the entry to add to
`auth.api_keys` in the policy. Only the key's hash goes in the policy. The key itself is
shown once and can't be recovered:

```console
$ sql-warden auth new-key support-bot --profile support
key: swk_...

Give it to support-bot: it is shown only this once, and can't be recovered.
```

See [Authentication](mcp-server.md#authentication).

## Environment variables

| Variable               | Same as       |
|------------------------|---------------|
| `SQL_WARDEN_CONFIG`    | `--config`    |
| `SQL_WARDEN_DSN`       | `--dsn`       |
| `SQL_WARDEN_PROFILE`   | `--profile`   |
| `SQL_WARDEN_AUDIT_DSN` | `--audit-dsn` |

A flag wins over its variable. Any other variable can be referenced from the policy file as
`${NAME}`; see [Secrets](policy.md#secrets).

## Developer tools

Two tools in the repository are not part of the installed package:

| Command                            | What it does                                                    |
|------------------------------------|-----------------------------------------------------------------|
| `uv run python -m tests.portal`    | the browser test page; see [tests/portal/README.md](https://github.com/Pruthvi-dhani/sql-warden/blob/main/tests/portal/README.md) |
| `uv run python dev/loadtest.py`    | measures a server under many callers at once, against throwaway databases of its own. `--callers`, `--requests`, `--sql` and `--pool-size` shape the run |
