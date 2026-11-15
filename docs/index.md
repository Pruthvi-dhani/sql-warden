# sql-warden documentation

sql-warden is a governed SQL gateway: an AI agent sends SQL over MCP, sql-warden checks it
against a policy, runs it only if every check passes, and records the request in a separate
audit database. The [README](../README.md) is the two-minute version.

## Start here

| Page                                  | What it covers                                                          |
|---------------------------------------|-------------------------------------------------------------------------|
| [Getting started](getting-started.md) | install, the demo databases, your first queries, the test portal, connecting Claude Code |
| [How it works](how-it-works.md)       | a request's path through the server, the ideas behind it, and where each lives in the code |
| [The checks](checks.md)               | what each check refuses, with examples, and every refusal code          |

## Writing a policy

| Page                                  | What it covers                                                          |
|---------------------------------------|-------------------------------------------------------------------------|
| [The policy file](policy.md)          | where the policy is read from, every section and key, profiles, and checking a policy |
| [Masking](masking.md)                 | hiding a column's values from a profile: the strategies, the hmac key, and what a query may do with a masked column |
| [Sessions and budgets](budgets.md)    | what a session is, the four limits and how each is counted, budgets across restarts and replicas, and budgets per caller |

## Running a server

| Page                                  | What it covers                                                          |
|---------------------------------------|-------------------------------------------------------------------------|
| [The MCP server](mcp-server.md)       | the five tools and what they return, serving over HTTP, and authentication with API keys and OIDC tokens |
| [Operating a server](operations.md)   | the container image, health checks, metrics, shutdown, the connection pool, and reloading the policy on `SIGHUP` |
| [Deploying](deploy.md)                | sql-warden as a central service: database roles, secrets, Kubernetes and ECS, the network, keeping the audit log |
| [The audit log](audit.md)             | what each record holds, failing closed, reading the log with `sql-warden audit`, and the append-only setup for production |
| [Defence in depth](defence-in-depth.md) | what the database enforces under each check, the role check a server makes before it starts, and what that doesn't cover |

## Reference

| Page                                  | What it covers                                                          |
|---------------------------------------|-------------------------------------------------------------------------|
| [Command reference](cli.md)           | every `sql-warden` command, its options, exit codes and environment variables |
| [Snowflake](snowflake.md)             | Snowflake as the warehouse: setup, what differs from Postgres, and how far it is tested |

## For contributors

- [plan.md](plan.md): the roadmap, and what was built at each step and why.
- [tests/portal/README.md](../tests/portal/README.md): the browser test page.
- The README's [Working on it](../README.md#working-on-it) section: the lint, type and test
  commands, and a map of the source tree.
