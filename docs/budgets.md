# Sessions and budgets

Every request belongs to a session, and a profile can cap what one session may use in
total: queries, cost, rows and refusals. A caller with a token can also have a budget of
their own across all their sessions. This page covers what a session is, how each limit is
counted, and where the counts are kept.

## Sessions

Every request belongs to a session, and its record in the audit log says which
(`session_id`, also in `--json` and the MCP results). A session is one caller's run of
requests:

| Caller                         | Its session                                                     |
|--------------------------------|-----------------------------------------------------------------|
| an agent over stdio            | the server process: the agent starts it, and it serves only that agent |
| a client over HTTP that connects | its connection; reconnecting starts a new session              |
| a client over HTTP that doesn't, with a token | its caller's own session, while the server runs   |
| a client over HTTP that doesn't, no token     | the server's one session, shared with every other such client |
| `sql-warden query` and `check` | each call, unless calls are given the same `--session NAME`      |

```bash
uv run sql-warden query "select count(*) from orders" --session nightly-report
uv run sql-warden check "select * from customers"     --session nightly-report
uv run sql-warden audit tail --session nightly-report
```

A name is up to 64 letters, digits, `.`, `_`, `:` or `-`. Over HTTP the id is sql-warden's own,
derived from the transport's `Mcp-Session-Id` rather than being it: whoever holds that header's
value can use the connection, so it stays out of responses and the audit log.

Whether an HTTP client connects depends on the MCP version it speaks. Before 2026-07-28 a
client opens a connection with a handshake and sends its `Mcp-Session-Id` with every request.
From 2026-07-28 on there are no connections over HTTP: each request stands alone, and nothing
on it says which other requests came from the same caller, except its token. With
[authentication](reference.md#authentication) each caller has a session of their own, kept while the
server runs: the same caller is the same session from any client, and a restarted server
starts everyone afresh. Without it those requests are all one session, the server's own: a
limit then holds for the server as a whole, so it can't be got around, but one caller can use
it up for the others.

Sessions are what [budgets](#session-budgets) count against.

## Session budgets

A budget caps what one [session](#sessions) may use in total. No limit is set unless you set
it, for every profile or for one:

```yaml
budgets:
  max_refusals: 50          # for every profile
profiles:
  public:
    budgets:                # public's own; max_refusals: null would lift the limit above
      max_queries: 25
      max_total_cost: 50000
      max_rows_returned: 500
      max_refusals: 10
```

| Limit               | Counts                                                              |
|---------------------|---------------------------------------------------------------------|
| `max_queries`       | queries that were allowed and sent to the database                  |
| `max_total_cost`    | the sum of their estimated costs, in the units of `cost.max_total_cost` |
| `max_rows_returned` | rows returned, over all of them                                     |
| `max_refusals`      | requests a check refused, dry runs included                         |

- **A session that reaches a limit is done.** Its next request is refused with
  `BUDGET_EXHAUSTED` before any other check runs, so it learns nothing more and the database
  isn't asked to plan anything. That is what `max_refusals` is for: an agent can't try query
  after query until one gets through.
- **A query must fit what is left.** Its estimated cost is counted before it runs, and one
  that costs more than the session has left is refused with `COST_OVER_BUDGET`; a cheaper one
  may still fit. Counting and checking are one step, so requests arriving together can't
  spend the same last query.
- **Rows are counted afterwards**, since they are only known once the query has run. The query
  that takes a session past `max_rows_returned` still comes back; the next is refused.
- **Dry runs are free**, except that a refused one counts as a refusal. A dry run is told
  whether the query would fit.
- **Not every refusal counts.** The budget's own don't, nor do the ones that aren't the
  caller's doing: `COST_UNAVAILABLE`, `CATALOG_UNAVAILABLE`, `BUDGET_UNAVAILABLE`,
  `AUDIT_UNAVAILABLE`, `INTERNAL_ERROR`.

Each result says what the session has used (`budget`, and a `session budget:` line in the
CLI), and the `budget_status` tool says it at any time:

```text
$ uv run sql-warden --config warden.example.yaml check "select id, name from products"
✓ parse   1.8 ms
✓ shape   0.1 ms
✓ access  33.9 ms
✓ cost    6.3 ms
✓ budget  0.0 ms
→ allowed (profile public; dry run, nothing was executed)
  cost: 1.02 of 10,000 allowed (most of it: Seq Scan on products)
  note: added LIMIT 51 (row cap 50 + 1 to detect truncation)
  session budget: 0 of 25 queries, 0 of 50,000 cost, 0 of 500 rows, 0 of 10 refusals used
  would run: SELECT id, name FROM public.products LIMIT 51
```

### Budgets outlive the server, and are shared by every server

A server keeps budgets in the audit database, next to the log: what each session has used is
one row there, charged in one locked transaction per request. Every server recording to that
database charges the same rows, so a session (or a caller, below) gets no more by reaching
another replica behind a load balancer, and requests arriving at once on different servers
can't spend the same last query. The first time a session is charged, its row starts from
what the audit log says it used: its queries that were sent to the database with their
estimated costs and rows, and its counted refusals, under the same profile. So CLI calls
given the same `--session` share one budget, though each is its own process:

```text
$ uv run sql-warden --config warden.example.yaml query "select id from products limit 3" --session nightly-2026-11-12
...
session budget: 1 of 25 queries, 0.06 of 50,000 cost, 3 of 500 rows, 0 of 10 refusals used
$ uv run sql-warden --config warden.example.yaml query "select id from products limit 3" --session nightly-2026-11-12
...
session budget: 2 of 25 queries, 0.12 of 50,000 cost, 6 of 500 rows, 0 of 10 refusals used
```

- **A name is one session for good.** Its budget never starts again, however old its
  records, so give each run its own name, say with the date in it.
- **If the usage can't be read, nothing runs**: the query is refused with
  `BUDGET_UNAVAILABLE`. A profile without limits never reads it, and keeps nothing there.
- **An agent's session doesn't survive a restart anyway.** Over stdio the session is the
  server process, and over HTTP it is the connection, which a restarted server has forgotten:
  the agent reconnects and gets a new session, with a new budget. A caller with a token is
  held to their own budget as well, which doesn't start again (next).
- The tables are `session_usage` and `caller_charges`, created with `audit_events`. The role
  servers connect to the audit database as needs to update them, which it doesn't need for
  the log itself.

### Budgets per caller

A session's budget starts afresh with every connection. A caller with a
[token](reference.md#authentication) can also be held to a budget of their own, over a rolling window,
across all their sessions: connecting again doesn't give them more.

```yaml
identity_budgets:           # for every caller with a token
  window_hours: 24          # "in any 24 hours"; the default
  max_queries: 500
  max_refusals: 50
profiles:
  public:
    identity_budgets:       # public's callers', merged with the above as budgets are
      max_rows_returned: 5000
```

The limits are the session budget's four, counted the same way. A request is held to both
budgets, its session's and its caller's, in one step: whichever runs out first refuses, and
the refusal says which (`this session's budget is used up` or `web-agent's budget for any 24
hours is used up`). Use counts while it is younger than the window, so a caller who reached a
limit can go on once enough of their earlier use is older than that. Each result's `budget`
has the caller's as `caller`, beside the session's, and so does `budget_status`.

Only callers with a token have one, so `identity_budgets` needs an `auth` section:
`config validate` says so rather than let it be ignored. A charge is kept as a row of
`caller_charges`, and deleted once it is older than the window.

## Where next

- [The budget check](checks.md#budget): the refusals a budget produces.
- [The policy file](policy.md): where `budgets` and `identity_budgets` sit in the policy.
