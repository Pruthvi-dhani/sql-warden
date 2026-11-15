# The MCP server

`sql-warden serve` is how agents reach sql-warden. It speaks
[MCP](https://modelcontextprotocol.io) over stdio or HTTP and offers five tools. This page
covers the tools and what they return, serving over HTTP, and authentication.

## Starting it

```bash
uv run sql-warden serve                      # stdio: for an agent that launches sql-warden itself
uv run sql-warden serve --transport http     # Streamable HTTP at http://127.0.0.1:8000/mcp
```

Over stdio the agent starts the server itself, and it serves that one agent.
[Getting started](getting-started.md#7-connect-an-agent) shows the Claude Code setup. Over
HTTP one server serves many clients; see [Over HTTP](#over-http).

## The tools

| Tool             | What it does                                                                  |
|------------------|-------------------------------------------------------------------------------|
| `run_query`      | checks the SQL and, if allowed, runs it and returns the rows                  |
| `check_query`    | dry run: the decision and the exact SQL that would run, nothing executed      |
| `list_tables`    | the tables and columns the profile may query, with types; cached for a minute |
| `describe_table` | one table's columns and types, and whether `SELECT *` works on it             |
| `budget_status`  | what the session has used of its budget and what is left; free, never refused |

The tools take only SQL (and, for `describe_table`, a table name). Nothing an agent sends
can choose its profile or its session.

## What comes back

Results are structured, so an agent can tell why a query was refused and fix it:

```json
{"refused": true, "check": "shape", "code": "NOT_A_SELECT",
 "reason": "only SELECT queries are allowed, not DELETE",
 "trace": [{"check": "parse", "passed": true, ...}, {"check": "shape", "passed": false, ...}]}
```

An allowed query comes back with `sql` (what ran), `rewrites`, the `trace` and a `result`
(`columns`, `rows`, `row_count`, `truncated`). Every response names its `session_id` and
`audit_id`. This is a whole one, from `run_query`:

```json
{"refused": false,
 "profile": "public",
 "session_id": "a76e0511a03d423281a9e4ef2ec08c9c",
 "sql": "SELECT id, name FROM public.products WHERE id = 3 LIMIT 51",
 "rewrites": ["added LIMIT 51 (row cap 50 + 1 to detect truncation)"],
 "masked_columns": [],
 "cost": {"total_cost": 4.5, "max_total_cost": 10000.0, "est_rows": 1, "top_node": "Seq Scan on products"},
 "budget": {"queries": {"used": 1.0, "limit": 25.0, "remaining": 24.0},
            "total_cost": {"used": 4.5, "limit": 50000.0, "remaining": 49995.5},
            "rows_returned": {"used": 1.0, "limit": 500.0, "remaining": 499.0},
            "refusals": {"used": 0.0, "limit": 10.0, "remaining": 10.0}},
 "trace": [{"check": "parse", "passed": true, "duration_ms": 2.759},
           {"check": "shape", "passed": true, "duration_ms": 0.069},
           {"check": "access", "passed": true, "duration_ms": 29.537},
           {"check": "cost", "passed": true, "duration_ms": 5.598},
           {"check": "budget", "passed": true, "duration_ms": 2.031}],
 "result": {"columns": ["id", "name"], "rows": [[3, "Product 3"]], "row_count": 1,
            "truncated": false, "duration_ms": 5.331},
 "audit_id": "143bce47-a693-4a95-88dd-6900a47baed8"}
```

Three details for whoever writes a client:

- Exact numbers come back as strings, and times as ISO 8601.
- `run_query` flags refusals and database errors as tool errors. `check_query` treats a
  refusal as an answer.
- `sql-warden query --json` and `check --json` print the same payload.

## Before it starts

Before it serves anything, `serve` asks the warehouse what its role can do, and doesn't start
as one that can write, or while the warehouse can't be asked: see
[Defence in depth](defence-in-depth.md).

## Over HTTP

Without an [`auth` section](#authentication) HTTP serves one profile, needs no token, and
only listens on loopback (`127.0.0.1`, `::1`, `localhost`). It rejects requests whose `Host`
or `Origin` isn't local, which stops web pages from reaching it through your browser. Where
it listens is `server.host` and `server.port` in `warden.yaml`, or `--host` and `--port`; an
address other machines can reach is refused by both, and by `config validate`.

It serves many clients at once. Each query runs in a worker thread, on a database
connection of its own for as long as it runs, so a slow one holds up nobody else's. What keeps one client from using the
server up:

| Limit                                 | Past it                                                    |
|---------------------------------------|------------------------------------------------------------|
| a request body of 256 KiB             | `413`, unread (a query is at most 20,000 characters)       |
| 10,000 open connections               | `503` for a new one until another closes                   |
| 30 minutes without a request          | the connection is closed; the client connects again, as a new [session](budgets.md#sessions) |
| a made-up or expired `Mcp-Session-Id` | `404`: a client can't choose its session, or join another's |

The connection limits are for clients that connect; see [Sessions](budgets.md#sessions) for
the ones that don't.

## Authentication

With an `auth` section, every HTTP request must carry `Authorization: Bearer <token>`, and
one server serves every profile: the token says who the caller is and which profile their
queries are checked against. Nothing an agent sends can choose another. stdio is not
affected: whoever starts the process has already picked its profile, with `--profile`.

```yaml
auth:
  api_keys:                      # made with `sql-warden auth new-key NAME --profile P`
    - name: support-bot          # who holds it: the audit log records this
      profile: support
      sha256: 2372e115...        # only the key's hash is kept
  oidc:                          # tokens from your identity provider
    issuer: https://login.example.com/
    audience: sql-warden         # what their aud claim must contain
    jwks_url: https://login.example.com/.well-known/jwks.json
    profile_claim: sql_warden_profile    # a claim that names the profile, or:
    # group_profiles: {data-analysts: support, dba: admin}   # profile by group
```

### Making an API key

```console
$ sql-warden auth new-key support-bot --profile support
key: swk_...

Give it to support-bot: it is shown only this once, and can't be recovered.
```

Add the entry it prints to `auth.api_keys`. Only the key's hash goes in the policy.

### What each request gets

| A request with                                    | Answer | Recorded as                    |
|---------------------------------------------------|--------|--------------------------------|
| no token, an unknown key, or a token that isn't valid (expired, for another service, signed with an unlisted key) | `401` | `UNAUTHENTICATED`, no profile |
| a valid token that gives no profile this server has, or groups that give two | `403` | `NO_PROFILE`, under the caller's name |
| an OIDC token while the provider's keys can't be fetched | `503` | `AUTH_UNAVAILABLE` |
| a token for a profile                             | the tools, as that profile | under the caller's name and profile |

A request that is turned away is never read: its body isn't parsed, and nothing runs. A
token never gets `default_profile`: a caller gets the profile their token names, or nothing.
Every record carries `identity` (an API key's name, or `oidc:<subject>`), shown by
`audit show` and filtered by `audit tail --identity NAME`. A connection belongs to the caller
who opened it: another token holding its `Mcp-Session-Id` gets `404`.

### OIDC tokens

OIDC tokens are JWTs. Their signature is checked against the provider's published keys, and
so are `iss`, `aud` and `exp` (with 30 seconds' leeway for clocks). Only public-key
signatures are accepted (`RS256` and `ES256` by default; `algorithms` lists others):
`none`, and shared-secret ones like `HS256`, are refused, so whoever can read the keys
can't make a token. The keys are fetched when first needed and kept for an hour; a token
signed with a key not seen yet fetches them again, at most once a minute.

Serving every profile means every profile's role must pass the [startup
check](defence-in-depth.md): `serve` doesn't start if any of them can write.

### Listening beyond loopback

With `auth`, the server can listen beyond loopback. Set `server.host` (say `0.0.0.0`) and
list in `server.allowed_hosts` the names clients reach it by; requests for any other name
are refused. `server.allowed_origins` lists web pages that may call it from a browser.
sql-warden speaks plain HTTP, so put a proxy that terminates TLS in front of it, and let
clients reach it only through the proxy: every request carries its token. `serve` warns when
it listens beyond loopback.

```yaml
server:
  host: 0.0.0.0
  port: 8000
  allowed_hosts: [warden.example.com]
```

## Where next

- [Operating a server](operations.md): the container image, health
  checks, metrics and reloading the policy.
- [Deploying](deploy.md): a whole deployment behind a TLS proxy.
- [Sessions and budgets](budgets.md): what a session is for each kind of client.
