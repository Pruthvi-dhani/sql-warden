# Defence in depth

sql-warden's checks are the first line, not the only one. Under each check, the database
enforces the same rule by itself, and a server refuses to start where it couldn't. This page
covers what backs each check up, the role check a server makes before it serves, and what
none of this covers.

## What backs each check up

The checks decide what an agent may run. Under each of them the database holds the same line
by itself, so one wrong check is not enough to change or leak data:

| If this were wrong                 | this still holds                                                                                                  |
|------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| the shape check lets a write pass  | the role has no privilege to write; Postgres also runs every query in a `READ ONLY` transaction, through a cursor |
| the access check lets a table pass | a profile with its own `dsn` connects as a role that can't read it                                                |
| the LIMIT it adds is lost          | the engine stops fetching at the row cap                                                                          |
| the cost estimate is far too low   | the statement timeout cancels the query                                                                           |
| a string is read where it doesn't end | the query sent is written out again from what was read, and Postgres is set to read strings the standard way  |

## The startup check

The first of these depends on the role, so a server looks before it serves. It asks the
warehouse what its role can do, and doesn't start as one that can write:

```console
$ sql-warden serve --dsn postgresql://app:...@db.internal/warehouse
Error: profile all: role app can change the warehouse (db.internal/warehouse as app):
  it can INSERT, UPDATE, DELETE on public.orders
  it can create tables in schema public
sql-warden only serves as a role that can read and nothing more: then the database refuses a write even if every check here is wrong.
```

### What counts as being able to write

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

### A role that can read too much

A server warns, on stderr, when the role can read more than its profile allows. Then the database
is not backing the access check up, and only that check keeps the profile from the rest:

```console
$ sql-warden serve --profile support
warning: profile support allows less than its role can read. warden_reader can also read:
  table public.employee_salaries
Only the access check keeps the profile from these. Give the profile a dsn of its own, for a role granted just what the profile allows.
```

## Checking every profile before a deploy

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

## When the warehouse changes under a policy

A table or column that is gone is refused to callers, so it is safe if not useful. A masked
column that is gone is worse: if it was renamed, a profile that allows the whole table reads
it under its new name, unmasked. A server still starts with either (a migration that drops a
column shouldn't take it down), and warns on stderr:

```console
warning: profile support masks columns its role can't see, so those masks protect nothing:
  public.customers.ssn
If a column was renamed, it is not masked under its new name: mask that one.
```

## What it does not cover

- **Grants made while it runs.** The role is looked at when the server starts and when it
  reloads; `/readyz` asks again whether it can write, at most every 10 seconds. The catalog
  is compared with the policy only at those two moments.
- **`query`, `check` and `tables` run by hand.** Whoever runs them holds the connection
  string and could use it without sql-warden; the server is the boundary, so the server is
  what is held to this.
- **Functions that write for their caller.** A `SECURITY DEFINER` function runs with its
  owner's privileges. The shape check refuses functions it doesn't know, and the read-only
  transaction stops a write inside one.
- **Snowflake outside the connection's database.** [Snowflake](snowflake.md) says how the role
  is read there.

## Where next

- [Deploying](deploy.md#1-the-warehouses-roles): creating the warehouse roles for a real
  deployment.
- [How it works](how-it-works.md): where these layers sit in a request's path.
