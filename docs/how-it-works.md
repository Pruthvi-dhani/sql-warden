# How it works

This page follows one request through sql-warden, explains the decisions behind the design,
and says where each part lives in the code. Read it before changing a check or adding one.

## The problem

An agent that writes its own SQL will, sooner or later, write a query you didn't want run:
one that reads a table it shouldn't, returns a column of SSNs, scans a billion rows, or
tries a `DELETE` because a prompt told it to. Instructions in the prompt can't prevent this,
because the prompt is the part an attacker or a confused model controls.

sql-warden puts the rules in a server between the agent and the database. The agent can
send any SQL it likes. What runs is decided by a policy the agent can't see or change.

## A request, start to finish

```
 agent ──MCP──▶ server ──▶ Warden
                              │
                              ├─ budget gate      has this session or caller used its budget up?
                              ├─ parse            read the SQL once, into a tree
                              ├─ shape            one read-only SELECT, within the structural rules
                              ├─ access           only tables and columns the profile allows
                              ├─ masking          masked columns only selected as they are, or counted
                              ├─ cost             the database plans the query; too expensive is refused
                              ├─ budget           does the estimated cost fit what the session has left?
                              │
                              ├─ run              the SQL, regenerated from the tree, read-only
                              ├─ mask             the result's masked columns
                              └─ record           one row in the audit database
```

1. **The request arrives.** An agent calls the `run_query` tool over MCP, or a person runs
   `sql-warden query`. Over HTTP with authentication, the caller's token decides which
   profile's rules apply. Nothing in the request can choose another: the tools take only SQL.
2. **The checks run in order, and the first refusal ends it.** Each check either passes or
   returns a refusal with a code and a reason. The result carries a trace: one entry per
   check that ran, with how long it took.
3. **The cost check asks the database.** It sends `EXPLAIN` for the query, which plans it
   without running it. This is the first time anything reaches the database, and it happens
   only after parse, shape, access and masking have passed, so the planner never sees SQL
   the other checks would refuse.
4. **An allowed query runs.** The SQL sent is written out again from the tree the checks
   approved. It runs as a read-only role, in a read-only transaction, with a statement
   timeout and a row cap.
5. **The result is masked**, for the columns the profile sees masked.
6. **The request is recorded** in the audit database, whatever happened: allowed, refused,
   failed or timed out. Then the answer goes back.

`check_query` (and `sql-warden check`) is the same path as a dry run: it stops after the
checks, runs nothing, and is recorded as a dry run.

Not every check is in every pipeline. The access check exists only for a profile with table
rules, the masking check only for a profile with masks, and the budget checks only where a
limit is set. With no `warden.yaml` at all, a query sees parse, shape and cost.

## The decisions behind it

### What runs is what was checked

The SQL is parsed once, by [sqlglot](https://github.com/tobymao/sqlglot), and every check
reads that one tree. An allowed query is then regenerated from the tree, with comments
dropped, and that is what the database receives. The text the agent sent never reaches it.

This closes a whole class of attack. If the parser and the database disagreed about where a
string ends or what a comment hides, a check could approve one query while the database ran
another. Here there is nothing left over for the database to read differently.

Checks may also change the tree, and say so. The shape check adds a `LIMIT` to a query
without one, and the access check pins each table to its schema (`products` becomes
`public.products`). The response lists these as `rewrites`, and shows the SQL that ran.

### Refusals are answers

A refusal is a structured result, not an opaque error. Shortened, it looks like this:

```json
{"refused": true, "check": "access", "code": "COLUMN_NOT_ALLOWED",
 "reason": "column category is not available to profile public",
 "trace": [{"check": "parse", "passed": true}, {"check": "shape", "passed": true},
           {"check": "access", "passed": false, "code": "COLUMN_NOT_ALLOWED"}]}
```

An agent can read the code and the reason and fix its query. Reasons are written for that
reader: they say what was wrong and, where it helps, what would work instead.

Reasons are also careful about what they reveal. A table that doesn't exist gets the same
answer as one the profile may not read, so a caller can't probe for names.

### When sql-warden can't decide, it refuses

Every failure path ends in a refusal, never in a query that ran unchecked:

| If this fails                                  | The query is refused with |
|------------------------------------------------|---------------------------|
| a check crashes                                | `INTERNAL_ERROR`          |
| the table catalog can't be read                | `CATALOG_UNAVAILABLE`     |
| the database can't be reached to plan the query | `COST_UNAVAILABLE`       |
| the session's usage can't be read              | `BUDGET_UNAVAILABLE`      |
| the audit database can't be written to         | `AUDIT_UNAVAILABLE`       |

The last one is the strictest. A server won't start without its audit database. If the
audit database goes away later, allowed queries are refused before they reach the warehouse.
If a record can't be written after a query has run, its rows are withheld. Nothing is
answered without a record.

### The database holds the same line

The checks decide what may run. Under each of them, the database enforces the same rule
independently, so one wrong check is not enough to change or leak data:

| If this were wrong                 | this still holds                                                    |
|------------------------------------|---------------------------------------------------------------------|
| the shape check lets a write pass  | the role can't write, and the transaction is read-only              |
| the access check lets a table pass | a profile with its own connection uses a role that can't read it    |
| the added `LIMIT` is lost          | the engine stops fetching at the row cap                            |
| the cost estimate is far too low   | the statement timeout cancels the query                             |

The first row depends on the role, so a server looks before it serves: it asks the database
what its role can do, and refuses to start as one that can write.
[Defence in depth](defence-in-depth.md) has the details, and what this doesn't
cover.

### One audit database, separate from the warehouse

The audit log is always Postgres, on a different instance from the warehouse, whatever the
warehouse is. An agent's queries can't reach it, and in production the server's role there
can add records but never change or remove one. Session budgets are kept in the same
database, which is how they hold across restarts and across several servers behind a load
balancer.

## The vocabulary

| Term         | Meaning                                                                             |
|--------------|-------------------------------------------------------------------------------------|
| **policy**   | the `warden.yaml` file: everything sql-warden enforces                              |
| **profile**  | the rules for one kind of caller: tables, columns, masks, limits, budgets           |
| **session**  | one caller's run of requests: an agent's connection, or CLI calls sharing `--session` |
| **identity** | who is calling, from their token: an API key's name, or an OIDC subject             |
| **engine**   | the warehouse behind sql-warden: Postgres or Snowflake                              |
| **decision** | the checks' verdict on one query: allowed or refused, with its trace                |
| **Warden**   | the object that takes SQL and returns a decision and, if allowed, rows; one per profile |

## Where it lives in the code

Everything is under `src/sql_warden/`:

| Module                 | What it holds                                                                 |
|------------------------|-------------------------------------------------------------------------------|
| `warden.py`            | the `Warden` facade: the whole path above, in `run()` and `check()`           |
| `pipeline/base.py`     | the `Check` protocol, the `CheckContext` the checks share, and the `Pipeline` runner |
| `pipeline/parse.py`, `shape.py`, `access.py`, `masking.py`, `cost.py`, `budget.py` | one check each |
| `pipeline/lineage.py`  | follows each output column back to its source columns, for masking            |
| `engines/base.py`      | the `Engine` protocol: `execute`, `explain`, `tables`, `role`                 |
| `engines/postgres.py`, `snowflake.py` | the two engines                                                |
| `catalog.py`           | the warehouse's tables and columns, cached, as a sqlglot schema               |
| `profiles.py`          | what a profile may read                                                       |
| `sessions.py`          | usage, budgets and the `SessionStore` protocol                                |
| `audit/`               | the audit schema, the writer (`sink.py`), the reader, retention, and the Postgres session store |
| `models.py`            | `RefusalCode`, `Refusal`, `Decision`, `QueryOutcome`                          |
| `config.py`            | the policy file's model and validation                                        |
| `server.py`            | the MCP tools, over stdio and HTTP                                            |
| `auth.py`              | API keys and OIDC tokens                                                      |
| `startup.py`           | the role check a server makes before it serves                                |
| `reload.py`            | reloading the policy on `SIGHUP`                                              |
| `pools.py`             | the Postgres connection pools: the warehouse's, and the audit database's (with `audit/connections.py`) |
| `metrics.py`           | the Prometheus metrics                                                        |
| `cli.py`, `render.py`  | the `sql-warden` command and its text output                                  |

### A check, in code

A check is an object with a name and one method:

```python
class Check(Protocol):
    name: str

    def run(self, ctx: CheckContext) -> Refusal | None:
        """Return a Refusal to stop the query, or None to let it continue."""
```

`ctx` holds the SQL, the parsed tree (`ctx.statements`, set by the parse check), the
dialect, and what earlier checks found. A check that changes the tree appends a note to
`ctx.rewrites`. The `Pipeline` runs checks in order, times each, stops at the first refusal,
and turns an exception in a check into an `INTERNAL_ERROR` refusal.

The checks read the SQL in the warehouse's dialect, so the shape, access and masking tests
run against both Postgres and Snowflake syntax.

### An engine, in code

An engine is anything with these four methods and a row cap:

| Method          | What it does                                                               |
|-----------------|----------------------------------------------------------------------------|
| `execute(sql)`  | runs one read-only query and returns at most `max_rows` rows               |
| `explain(sql)`  | returns the planner's estimate, without running the query                  |
| `tables()`      | lists the tables and columns the role can read                             |
| `role()`        | reports the role and every way it could change the database                |

The checks and the `Warden` only use this protocol, which is why the unit tests run against
a fake engine with no database at all.

## Where next

- [The checks](checks.md): what each one refuses, and every refusal code.
- [plan.md](https://github.com/Pruthvi-dhani/sql-warden/blob/main/docs/plan.md): what was built at each step, with the reasoning and the trade-offs.
