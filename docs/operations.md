# Operating a server

This page is for whoever runs sql-warden as an HTTP service: the container image, the
health and metrics endpoints, shutdown, the connection pools, and changing the policy
without a restart. [Deploying](deploy.md) has a whole deployment, end to end: the databases'
roles, secrets, Kubernetes and ECS, the network, and keeping the audit log.

## The container image

The repository's `Dockerfile` builds an image of the HTTP server: two stages, so the image
holds the installed package and its dependencies but not uv or the source tree, running as
an unprivileged user of its own (uid 10001).

```bash
docker build -t sql-warden .                                  # Postgres only
docker build -t sql-warden --build-arg EXTRAS=snowflake .     # with the Snowflake engine
docker run -p 8000:8000 -v "$PWD/warden.yaml:/etc/sql-warden/warden.yaml:ro" sql-warden
```

It serves `serve --transport http --host 0.0.0.0`, so its config needs an `auth` section and
`server.allowed_hosts`.

## Health checks

Beside `/mcp` the server answers three paths that need no token, for whatever runs it:

| Path       | Answers                                                                                |
|------------|----------------------------------------------------------------------------------------|
| `/healthz` | `200 ok` while the process answers at all: the liveness probe                         |
| `/readyz`  | `200` if the audit database answers and every profile's warehouse role answers and still can't write; otherwise `503` with the names of what fails (`audit`, `warehouse:public`), the reasons going to the log. Asked at most every 10 seconds |
| `/metrics` | Prometheus's text format                                                               |

Route only `/mcp` through the public proxy: these three are for the cluster.

## Metrics

`/metrics` serves these, in Prometheus's text format:

| Metric                                   | What it counts                                                    |
|------------------------------------------|-------------------------------------------------------------------|
| `sql_warden_requests_total`              | requests answered, by `profile`, `kind` (query, check) and `decision` |
| `sql_warden_refusals_total`              | refusals, by `profile`, the `check` that refused, and `code`      |
| `sql_warden_request_duration_seconds`    | a histogram of how long requests took, by `profile` and `kind`    |
| `sql_warden_estimated_cost`              | a histogram of the planner's estimates, by `profile`              |
| `sql_warden_rows_returned_total`         | rows returned, by `profile`                                       |
| `sql_warden_audit_write_failures_total`  | requests answered `AUDIT_UNAVAILABLE`                             |
| `sql_warden_auth_refusals_total`         | HTTP requests turned away before reaching a profile, by `code`    |
| `sql_warden_requests_in_flight`          | requests being answered right now                                 |
| `sql_warden_config_reloads_total`        | reloads of the policy on `SIGHUP`, by `outcome` (applied, failed) |
| `sql_warden_config_last_reload_successful` | `0` while the policy file as it is now failed to load, else `1` |
| `sql_warden_pool_connections`            | connections a pool has open, by `pool`: `warehouse` (with `profile`), `audit` or `budgets` |
| `sql_warden_pool_connections_in_use`     | connections lent out right now                                    |
| `sql_warden_pool_requests_waiting`       | requests waiting for a connection, because every one is in use    |
| `sql_warden_pool_timeouts_total`         | requests that got none within the pool's `timeout_s`              |

No label holds anything a caller chooses (an identity, say), so no caller can make the set
grow.

Three are worth an alert:

| Alert when                                             | Because                                              |
|--------------------------------------------------------|------------------------------------------------------|
| `sql_warden_audit_write_failures_total` rises          | requests are being refused: the audit database is unreachable |
| `sql_warden_config_last_reload_successful` is `0`      | the policy file and what is served differ            |
| `sql_warden_pool_timeouts_total` rises                 | requests are waiting too long for a connection (`pool` says to which database) |

## Shutdown and concurrency

On `SIGTERM` the server stops taking connections and gives the requests it has
`server.shutdown_grace_s` (30) seconds to finish. `server.max_concurrent_requests` (32) is how
many requests it answers at once; the rest wait.

## The connection pools

A server keeps its connections to a Postgres warehouse in a pool, one per profile
(`warehouse.pool`: up to `max_size`, 10, each), instead of opening one for every request;
so the warehouse must allow servers × profiles × `max_size` connections. Each connection is
checked as it is lent and reset with `DISCARD ALL` as it comes back, so nothing one request
leaves on it reaches the next. A request that finds every connection in use waits up to
`timeout_s` (5) and is then answered as when the warehouse can't be reached. Snowflake keeps
one session per profile open instead.

The audit database gets two pools of its own (`audit.pool`: up to `max_size`, 5, each): one
for records and one for every profile's budgets, so the audit database must allow servers ×
2 × `max_size`. They are kept apart so that charges waiting on each other's locks can't take
the connections the records need. Only sql-warden's own statements run on them, so they are
checked as they are lent but not reset. Fail-closed is as before: a record that gets no
connection within `timeout_s` is a record that couldn't be written, and the request is
refused `AUDIT_UNAVAILABLE` before the warehouse is asked; a charge that gets none is
`BUDGET_UNAVAILABLE`.

`dev/loadtest.py` measures a server under many callers at once, against throwaway databases
of its own.

## Reloading the policy

On `SIGHUP` the HTTP server reads its policy file again (`docker kill --signal HUP`, or
`kill -HUP` on its process), so keys can be revoked and issued, and profiles added or
changed, without a restart. The new policy is built in full first: the file validated, and
every profile's role looked at as at startup. Only then is it served, all at once. A request
already being answered finishes with the policy it started with, and one whose token was
checked a moment before the swap is answered by the policy that checked it. If anything
fails (a typo, a profile whose role can now write, a warehouse that can't be reached) the
server goes on with the policy it had and logs why on stderr:

```console
could not reload /etc/sql-warden/warden.yaml, so the policy loaded before is still served: /etc/sql-warden/warden.yaml: invalid config
  (top level): auth gives api key helpdesk the profile 'suport', but the config defines support
```

`sql_warden_config_last_reload_successful` stays `0` until a reload succeeds, which is
something to alert on: the file and what is served differ. Three things take a restart, and
a reload that changes them is refused: the `audit` section, the `server` section, and adding
or removing `auth`. Command-line flags still win over the file after a reload, and a server
of one profile keeps serving the one it started with. Over stdio there is no reload: the
agent that started the server restarts it.

In Kubernetes, mount the policy from a ConfigMap as a directory, not with `subPath` (a file
mounted with `subPath` is never updated), and send `SIGHUP` once the new file is in place.

## Where next

- [Deploying](deploy.md): the manifests, roles and secrets for a real deployment.
- [The MCP server](mcp-server.md): the tools, HTTP limits and authentication.
- [The policy file](policy.md): the `server`, `warehouse.pool` and `audit.pool` settings.
