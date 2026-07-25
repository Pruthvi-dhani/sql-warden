# sql-warden — Plan

A **governed SQL gateway for AI agents, exposed over MCP**. It lets an agent query a real
database and enforces every safety property *server-side*, rather than requesting it in a
prompt.

The demo is deliberately mundane: connect an MCP client to a seeded fintech database, ask
"which merchants drove the most chargebacks last quarter", get an answer. The project is
everything that stops that from being a catastrophe — a query admission pipeline, a
pre-execution cost gate, column masking, per-session budgets, and a full audit trail.

Two engines ship: **PostgreSQL** (OLTP) and **Snowflake** (warehouse). They were chosen
because they are *dissimilar* — different cost models, different enforcement primitives,
different exfiltration surfaces. That dissimilarity is what makes the engine abstraction
a real design rather than a cosmetic one.

---

## 1. Goals & Non-Goals

### Goals (MVP)
- An MCP server exposing a small, read-only tool surface: schema discovery, table
  description, query explain, query execution.
- A **query admission pipeline**: parse → shape → resolve → policy → cost → execute →
  record. Any stage can reject, with a typed reason code.
- **AST-level SQL validation** via sqlglot. Allowlist of permitted node types, never a
  regex blocklist.
- **Pre-execution cost gating** using the engine's own planner, with per-engine
  thresholds expressed in that engine's native unit.
- **Column-level masking and table-level denial**, driven by a declarative policy file.
- **Defence in depth**: even if the parser admits a bad query, the database role must
  refuse it.
- **Per-session query budgets** and fingerprint-based rate limiting, because agents loop.
- **Full audit trail** of every attempt, including rejections, written to a database
  separate from the one being queried.
- Two engine implementations (`postgres`, `snowflake`) behind one `Engine` protocol.
- An **engine conformance suite** that both implementations must pass identically.
- A **per-engine red-team corpus** of adversarial SQL that must be rejected.
- A seeded demo dataset large enough that the cost gate genuinely fires.

### Non-Goals (MVP)
- **Prompt-injection defence.** Data returned from the database can contain adversarial
  instructions. This is a client-side trust problem and cannot be solved at this layer.
  The server marks returned data as untrusted content and documents the threat. Stated
  explicitly rather than papered over.
- **Write access of any kind.** No DML, no DDL, no transactions the agent controls.
- **Engines beyond Postgres and Snowflake.** The seam exists; a third engine requires its
  own threat model and is not inherited.
- **Natural-language-to-SQL.** The agent writes the SQL. This server governs it.
- **Multi-tenant identity.** A single configured principal per server instance for MVP.

### Stretch (post-MVP)
- Row-level policy (Snowflake row access policies; Postgres RLS).
- A `sample_table` tool with policy-safe canned sampling.
- Result caching keyed on query fingerprint, to cut repeat agent spend.
- BigQuery engine (third implementation, would validate the seam further).
- A policy linter that flags unmasked columns matching PII heuristics.

---

## 2. Tech Stack

- **Python 3.12**, async throughout
- **MCP Python SDK** for the server and tool surface
- **sqlglot** for parsing, AST inspection, and policy rewriting
- **psycopg 3** (async) for Postgres
- **snowflake-connector-python** for Snowflake
- **Pydantic v2** for config, policy, and tool schemas
- **PostgreSQL 16** — supported engine *and* the audit store
- **Snowflake** — supported engine
- **Testcontainers** + **pytest** (`pytest-asyncio`) for tests
- **Prometheus** (`prometheus-client`) for metrics
- **GitHub Actions** for CI; **ruff** + **mypy --strict** as gates
- Packaging: **uv** / `pyproject.toml`, single distributable package

---

## 3. Repository Layout

```
sql-warden-mcp/
├── src/sql_warden/
│   ├── server.py             MCP server, tool registration, envelope shaping
│   ├── pipeline/
│   │   ├── admission.py      the seven-stage pipeline, orchestration only
│   │   ├── stages.py         Parse | Shape | Resolve | Policy | Cost | Execute | Record
│   │   └── decisions.py      Decision, DenyReason enum, stage results
│   ├── engines/
│   │   ├── base.py           Engine protocol, CostEstimate, EnforcementModel, Guard
│   │   ├── postgres.py       PostgresEngine
│   │   └── snowflake.py      SnowflakeEngine
│   ├── policy/
│   │   ├── model.py          policy schema (deny / mask, strategies)
│   │   └── rewrite.py        AST rewriting for server-enforced masking
│   ├── catalog.py            introspection + TTL cache
│   ├── budget.py             per-session budget, fingerprint rate limiting
│   ├── audit.py              audit record + writer (separate DB)
│   └── metrics.py            Prometheus binders
├── tests/
│   ├── unit/                 parser guards, policy rewrite, budget math, fingerprints
│   ├── conformance/          ONE suite, parametrised over every Engine impl
│   └── redteam/
│       ├── shared.sql        engine-agnostic attacks
│       ├── postgres.sql      pg_read_file, COPY TO PROGRAM, dblink, ...
│       └── snowflake.sql     COPY INTO stage, RESULT_SCAN, external functions, ...
├── demo/
│   ├── seed_postgres.sql     generate_series seed, deterministic
│   ├── seed_snowflake.sql    same shape, clustered so pruning matters
│   └── policy.example.yaml
├── docker-compose.yml        Postgres (target) + Postgres (audit)
├── plan.md
└── implementation-plan.md
```

Rationale: `pipeline/` holds orchestration and knows nothing engine-specific; `engines/`
holds everything that differs. If a stage needs an `if engine == "snowflake"` branch, that
is a signal the capability belongs on the `Engine` protocol instead.

---

## 4. Component Design

### 4.1 MCP tool surface

Small and read-only by construction. Five tools:

| Tool | Purpose |
|---|---|
| `list_schemas()` | Allowlisted schemas only. The agent never learns what it cannot reach. |
| `list_tables(schema)` | Tables in an allowlisted schema, denied tables omitted. |
| `describe_table(schema, table)` | Columns, types, PK/FK, row estimate, **and which columns are policy-restricted**. |
| `explain_query(sql)` | Dry run. Returns the admission decision and cost estimate without executing. |
| `run_query(sql, max_rows?)` | The guarded execution path. |

`describe_table` surfacing the policy is deliberate: an agent that can see a column is
masked will stop trying to query it, which cuts wasted turns and cuts rejected-query spend.

`explain_query` exists so an agent can self-correct cheaply, and so a human operator can
ask "would this have been allowed?" without running it.

### 4.2 The admission pipeline

Every `run_query` passes through seven stages. Each returns `Allow` or
`Deny(reason_code, message)`. Deny reason codes are a closed enum — they drive the audit
log, the metrics labels, and the message the agent sees so it can correct itself.

1. **PARSE** — sqlglot parses the SQL in the engine's dialect. A parse failure is a
   rejection, never a fallback to "send it anyway and let the DB decide".
2. **SHAPE** — exactly one statement, and it must be a `SELECT` or a `WITH` whose final
   expression is a `SELECT`. Every other node type is refused by allowlist. Engine-specific
   `Guard`s also run here (dangerous functions, stage references, UDF calls).
3. **RESOLVE** — walk the AST and resolve every table and column reference against the
   cached catalog. Unknown objects are rejected. References outside allowlisted schemas are
   rejected. This is also what makes stage 4 possible.
4. **POLICY** — apply the policy. Denied tables reject the query outright. Masked columns
   are either rewritten in the AST (Postgres) or left to the engine's native masking
   (Snowflake), per that engine's `EnforcementModel`.
5. **COST** — ask the engine for a pre-execution estimate and compare it to that engine's
   threshold, in that engine's unit. Reject if over.
6. **EXECUTE** — run against a read-only principal, with a statement timeout and an
   injected row cap.
7. **RECORD** — build the result envelope and write the audit entry.

Stages 1 through 5 are pure and require no execution, which is why `explain_query` is
simply "run the pipeline, stop before stage 6".

### 4.3 The `Engine` seam — abstract capabilities, not policy

The naive interface is wrong:

```python
def estimate_cost(sql) -> float   # WRONG
```

A Postgres planner cost of 50,000 and 4 GB scanned in Snowflake are not comparable, and
collapsing them into one float yields a threshold that is meaningless on at least one
engine. Estimates carry their unit; thresholds are configured per engine.

```python
class CostUnit(StrEnum):
    PLANNER_COST = "planner_cost"          # Postgres, unitless
    BYTES_SCANNED = "bytes_scanned"        # Snowflake
    PARTITIONS_SCANNED = "partitions_scanned"

class CostEstimate(BaseModel):
    unit: CostUnit
    value: float
    is_pre_execution: bool   # can we know this WITHOUT spending compute?

class Enforced(StrEnum):
    NATIVE = "native"    # the engine enforces it
    SERVER = "server"    # sql-warden enforces it
    NONE = "none"

class EnforcementModel(BaseModel):
    readonly:  Enforced
    masking:   Enforced
    row_limit: Enforced
    timeout:   Enforced

class Engine(Protocol):
    name: str
    sqlglot_dialect: str

    def guards(self) -> Sequence[Guard]: ...
    def enforcement(self) -> EnforcementModel: ...
    async def introspect(self, conn) -> Catalog: ...
    async def estimate(self, conn, ast: exp.Expression) -> CostEstimate: ...
    def readonly_session(self, conn) -> AsyncContextManager[Session]: ...
    def apply_row_limit(self, ast: exp.Expression, n: int) -> exp.Expression: ...
```

`EnforcementModel` is the important one, and it is not decoration. The audit entry records
**where** each control was enforced, so a reviewer can see that masking on Postgres came
from an AST rewrite while masking on Snowflake came from a native policy attached to the
column. Asserting that controls apply is cheap; proving where they applied is not.

### 4.4 PostgresEngine

- **Dialect**: `postgres`.
- **Introspection**: `information_schema.columns`, `pg_class.reltuples` for row estimates,
  `pg_constraint` for PK/FK.
- **Cost**: `EXPLAIN (FORMAT JSON)` → `Plan."Total Cost"` and `Plan Rows`.
  `is_pre_execution=True`, cheap but requires a connection and a planned statement.
- **Read-only**: `Enforced.NATIVE`. A dedicated role holding only `USAGE` and `SELECT`,
  with `default_transaction_read_only = on`, and every query wrapped in `BEGIN READ ONLY`
  with `SET LOCAL statement_timeout`.
- **Masking**: `Enforced.SERVER` — AST rewrite. Column `GRANT`s are configured as the
  backstop, so a masked column is one the role cannot select anyway.
- **Guards**: `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `lo_import`/`lo_export`,
  `COPY`, `dblink`, `postgres_fdw`, `pg_sleep`, `DO` blocks, `CREATE FUNCTION`,
  set-returning function abuse.

### 4.5 SnowflakeEngine

- **Dialect**: `snowflake`.
- **Introspection**: `INFORMATION_SCHEMA` views plus `SHOW` where needed.
- **Cost**: `EXPLAIN USING JSON` → partitions assigned/total and bytes assigned.
  **`is_pre_execution=True` and, notably, free** — Snowflake compiles the plan without a
  running warehouse, so a query can be rejected before a single credit is spent. *Verify
  against current docs before relying on it; if it ever requires a warehouse, the gate
  still works but stops being free.*
- **Read-only**: `Enforced.NATIVE`, but via **RBAC only** — Snowflake has no read-only
  transaction mode, so the role holds `USAGE` + `SELECT` and no `CREATE` anywhere. This
  asymmetry with Postgres is exactly the kind of thing the abstraction must not hide.
- **Masking**: `Enforced.NATIVE` — masking policies attached to the column, which apply
  even to a query that never passes through sql-warden.
- **Timeout**: `STATEMENT_TIMEOUT_IN_SECONDS` on the session.
- **Budget backstop**: a **resource monitor** on a dedicated extra-small warehouse with
  aggressive auto-suspend. This is the control the server cannot exceed even if every
  other layer fails.
- **Audit corroboration**: every statement carries a `QUERY_TAG` containing the audit id,
  so `ACCOUNT_USAGE.QUERY_HISTORY` can be reconciled against the local audit log. This
  turns "my audit log is complete" from an assertion into something provable.
- **Guards**: `COPY INTO <location>` (direct exfiltration to attacker-controlled storage),
  `CREATE STAGE`, `PUT`/`GET`, external functions, external access integrations,
  Java/Python/Scala UDFs, stored procedures, `CREATE TASK`, cross-database and share
  access, `SYSTEM$` functions, and **`RESULT_SCAN`** (which can read a prior query's
  results in-session and sidestep policy applied at parse time).

### 4.6 Policy model

Declarative, versioned, and reviewable in a PR:

```yaml
version: 1
allowed_schemas: [analytics]

tables:
  - match: analytics.kyc_documents
    action: deny

  - match: analytics.customers
    columns:
      email:         { action: mask, strategy: sha256 }
      date_of_birth: { action: mask, strategy: fixed, value: "[REDACTED]" }
      account_number:{ action: mask, strategy: last4 }
```

Two enforcement modes, both used in the demo: **table-level denial** (`kyc_documents`) and
**column-level masking** (`customers`). Denial produces a typed rejection; masking produces
a successful query with a `redactions` list in the envelope, so the model is told what it
did not see rather than being silently misled.

### 4.7 Result envelope

The envelope, not a bare rowset, because the consumer is a language model:

```json
{
  "engine": "snowflake",
  "columns": ["merchant_id", "chargeback_count"],
  "rows": [["m_1029", 412]],
  "row_count": 500,
  "truncated": true,
  "limit_applied": 500,
  "redactions": ["analytics.customers.email"],
  "cost": { "unit": "bytes_scanned", "value": 1240000000 },
  "enforcement": { "masking": "native", "readonly": "native" },
  "audit_id": "01J...",
  "content_trust": "untrusted"
}
```

`truncated` and `content_trust` exist for LLM-specific reasons; see §6.

### 4.8 Budgets and rate limiting

Per session and per principal: a maximum query count, a maximum cumulative estimated cost,
and a fingerprint-based rate limit. Fingerprints are the AST with literals normalised out,
so a loop issuing the same query with a rolling date is recognised as one pattern.

This is not a nicety. An agent stuck in a retry cycle will hammer a database in a way no
human ever does, and on Snowflake it does so denominated in money.

### 4.9 Audit

One row per **attempt**, allowed or denied:

```
audit(
  id, ts, principal, session_id, engine,
  raw_sql, fingerprint,
  decision,            -- ALLOW | DENY
  deny_reason,         -- closed enum, null when allowed
  stage,               -- which stage rejected it
  cost_unit, cost_value,
  rows_returned, truncated, duration_ms,
  redactions jsonb, enforcement jsonb,
  engine_query_id      -- Snowflake query id / Postgres pid, for reconciliation
)
```

**The audit database is not the database being queried.** If a policy bug or parser bypass
ever reaches the target, the evidence of what happened must not sit inside the blast
radius. Separate database, or at absolute minimum a separate schema whose role the query
principal has no grants on.

---

## 5. Configuration

```yaml
server:
  engine: snowflake            # or postgres
  policy_file: ./policy.yaml

limits:
  max_rows: 500
  statement_timeout: 30s

cost_gate:
  postgres:
    unit: planner_cost
    max: 250000
  snowflake:
    unit: bytes_scanned
    max: 5_000_000_000        # 5 GB

budget:
  max_queries_per_session: 50
  max_cost_per_session: 50_000_000_000
  rate_limit: { per_fingerprint: 5, window: 60s }

audit:
  dsn: ${AUDIT_DATABASE_URL}   # deliberately NOT the target database

catalog:
  cache_ttl: 5m
```

Cost thresholds are nested per engine because the units are not interchangeable. A single
top-level `max_cost` would be a design error.

---

## 6. Architectural Decisions to Document (the senior-IC signal)

These get first-class treatment in the README.

1. **Parse, never pattern-match; allowlist, never blocklist.** Regex blocklists die to
   comments, string literals, casing, unicode escapes, and nested CTEs. An AST is the only
   sound approach. And the rule is an allowlist of permitted node types, because a
   blocklist is only ever as good as the author's imagination.

2. **The parser is not the security boundary.** This is the strongest answer in the
   project and exists because the obvious challenge is "what if your parser has a bug?"
   The database role is the boundary: `SELECT`-only grants, no `CREATE`, and on Postgres a
   read-only transaction. The parser exists for fast, explanatory rejections and for cost
   control. If it fails open, the engine still refuses. Two independent mechanisms, either
   one sufficient.

3. **Cost gate before execution; timeout as backstop, not as the control.** A statement
   timeout only fires once the I/O has already been burned. `EXPLAIN` rejects the scan
   before it starts. But planner estimates are routinely wrong, so the timeout stays.
   Both, not either.

4. **Abstract capabilities, not policy.** Cost estimates carry units; enforcement is
   *declared* per engine rather than assumed uniform. The alternative — a lowest-common-
   denominator interface — would have forced Snowflake's native masking to be ignored and
   Postgres's read-only transactions to go unused.

5. **Masking is server-side, and where it was enforced is recorded.** Never instruct the
   model not to look. On Snowflake the native masking policy is the enforcement and the
   AST rewrite is skipped; on Postgres the rewrite is the enforcement and column `GRANT`s
   are the backstop. The audit entry records which, because "a control applied" and "this
   specific mechanism applied" are different claims.

6. **Truncation is explicit and structured.** If results are silently capped at 500 rows,
   the model will state as fact that there are 500 customers. The envelope carries
   `row_count`, `truncated`, and `limit_applied`, and the tool description instructs the
   model to disclose truncation. This is an LLM-specific failure mode with no analogue in
   a normal REST API, and designing for the actual consumer is the point.

7. **Rejections are audited as carefully as successes, in a separate database.** The
   denied queries are the interesting security signal, and the evidence must live outside
   the blast radius.

8. **A per-session budget, because agents loop.** On Postgres a runaway agent wastes CPU.
   On Snowflake it spends money. Rate limiting on a literal-normalised query fingerprint
   is the mitigation, with a resource monitor as the control of last resort.

9. **Prompt injection is out of scope, deliberately and explicitly.** A returned row can
   say "ignore previous instructions". The server cannot fix that, because it is a client
   trust problem. What it does is mark all returned data `content_trust: untrusted` and
   document the threat. Naming a threat you did not solve, and explaining why it is not
   solvable at this layer, is worth more than pretending the surface is covered.

10. **Two engines, deliberately dissimilar; "pluggable" is a bounded claim.** Postgres and
    Snowflake are OLTP and warehouse, sharing almost nothing in cost model, enforcement
    primitives, or exfiltration surface. Had the pair been Postgres and MySQL, the
    abstraction would be cosmetic. The README states plainly that two engines are
    implemented and threat-modelled, and that **adding a third requires threat-modelling
    it** — the dangerous-function list is not inheritable. On a security tool, an
    assumed-safe engine nobody threat-modelled is the worst possible failure.

---

## 7. Threat Model & Red-Team Corpus

The corpus is the artifact that sells this project — the equivalent of the chaos test in
the outbox starter. A file of adversarial SQL, every line of which must be rejected, run
against a real engine.

**Shared (engine-agnostic):** stacked statements (`SELECT 1; DROP TABLE users`), writes
smuggled inside CTEs (`WITH x AS (DELETE FROM ... RETURNING *) SELECT * FROM x`),
comment-obfuscated payloads, unicode and casing evasion, cross-schema reads outside the
allowlist, recursive-CTE resource bombs, and masked-column laundering (aliasing or wrapping
a masked column in an expression to escape the rewrite).

**Postgres:** `COPY ... TO PROGRAM`, `pg_read_file`, `lo_export`, `dblink` to an external
host, `pg_sleep` resource exhaustion, `DO` blocks.

**Snowflake:** `COPY INTO 's3://attacker/'`, `CREATE STAGE` followed by `GET`, external
functions and external access integrations for network egress, Java/Python UDFs,
`RESULT_SCAN` against a prior query in the session, cross-database access via shares, and
`SYSTEM$` functions.

Paired with a **defence-in-depth test**: force a query past the parser and assert the
engine role refuses it anyway. That test is what makes decision 2 a demonstrated property
rather than a claim.

---

## 8. Testing Strategy

- **Unit** — parser guards, allowlist completeness, policy rewriting, masked-column
  laundering, cost-unit handling, budget arithmetic, fingerprint stability. No database.
- **Conformance** — **one** abstract suite, parametrised over every `Engine`
  implementation: introspection shape, read-only enforcement, cost estimation, masking,
  row limits, timeout behaviour, audit record shape. Running the identical suite green
  against both engines *is* the proof of pluggability, and is far better evidence than a
  paragraph asserting it.
- **Red team** — the §7 corpora, asserting rejection and the correct `deny_reason`.
- **Defence in depth** — parser bypassed, engine must still refuse.

**CI split, stated openly in the README rather than hidden:**

| Suite | Where | When |
|---|---|---|
| Unit | GitHub Actions | Every push |
| Conformance (Postgres) | Testcontainers | Every push |
| Red team (shared + Postgres) | Testcontainers | Every push |
| Conformance (Snowflake) | Live account | On demand / scheduled |
| Red team (Snowflake) | Live account | On demand / scheduled |

Policy correctness is unit-testable and gated on every commit. Engine enforcement for
Snowflake needs a live account, so it runs on demand. Postgres is not a stand-in for the
"real" engine here — it is a first-class supported engine that happens to also be
hermetically testable, which is precisely why shipping both was the right call.

---

## 9. Demo Dataset

`customers`, `accounts`, `transactions`, `merchants`, `chargebacks`, plus `kyc_documents`
which is denied outright. That gives both enforcement modes in one demo: column masking on
`customers.email`, `date_of_birth`, and `account_number`, and table denial on
`kyc_documents`.

Generated in pure SQL with `generate_series` and a fixed `setseed`, so it is deterministic,
dependency-free, reproducible across screenshots and CI, and seeds millions of rows in
seconds.

**Sized so the cost gate actually fires:** roughly 10k customers, 25k accounts, 5M
transactions. `SELECT * FROM transactions` must be genuinely expensive, because a guardrail
that only triggers on a toy table convinces nobody, and this is the single most-screenshotted
moment in the repo.

Note the tuning differs per engine and the numbers do not port. On Postgres the target is
crossing a planner cost threshold. On Snowflake it is micro-partitions scanned, so the
table must be large enough and clustered such that a poorly-filtered query genuinely scans
a lot of partitions. CI runs against a small fixture; the large seed is for the manual demo
and one dedicated cost-gate test.

---

## 10. Deliverables

- The `sql-warden` MCP server, runnable against either engine from one config file.
- `docker compose up` giving a target Postgres and a separate audit Postgres, seeded.
- README: architecture diagram, the tool surface, the admission pipeline, the engine
  comparison table, the decision log (§6), the threat model (§7), and the CI split (§8).
- The red-team corpora, and a recorded transcript of an MCP client driving the server —
  including a rejected malicious query alongside its audit entry.

---

## 11. Milestones

**M0 — Scaffolding**
Package layout, `pyproject.toml`, ruff + mypy strict, CI, Testcontainers Postgres base,
compose stack with target and audit databases.

**M1 — Pipeline skeleton + Postgres engine**
`Engine` protocol, `PostgresEngine`, stages PARSE/SHAPE/RESOLVE, catalog introspection with
TTL cache, `DenyReason` enum. Shared red-team corpus green.

**M2 — Enforcement**
Read-only role and transaction, row caps, statement timeout, cost gate via `EXPLAIN`,
Postgres red-team corpus green, defence-in-depth test green.

**M3 — Policy + audit**
Policy model and AST rewriting, masked-column laundering tests, audit writer against the
separate database, result envelope with truncation and redaction reporting.

**M4 — MCP surface**
The five tools, tool descriptions written for a model rather than a human, `explain_query`
dry run, end-to-end transcript against a real MCP client.

**M5 — Snowflake engine**
`SnowflakeEngine`, `EXPLAIN USING JSON` cost extraction, native masking policies, RBAC
setup scripts, resource monitor, `QUERY_TAG` audit reconciliation, Snowflake red-team
corpus. **Conformance suite green against both engines** — the milestone that proves the
seam.

**M6 — Budgets, metrics, docs**
Session budgets and fingerprint rate limiting, Prometheus metrics, the full README with the
decision log and engine comparison table.

**Stretch**
Row-level policy, result caching keyed on fingerprint, a third engine, a PII policy linter.

> A stage-by-stage build plan with concrete steps, per-stage testing, and exit criteria
> lives in [implementation-plan.md](implementation-plan.md).

---

## 12. Open Questions

- Masked-column laundering is the hardest correctness problem here: `SELECT upper(email)`,
  `SELECT email AS e`, `SELECT substr(email,1,3)`, or a CTE that projects the column
  before the rewrite sees it. Is post-resolution rewriting sufficient, or does masking have
  to be enforced natively on both engines to be sound? *Current lean: rewrite at the
  resolved-column level and treat the native `GRANT`/masking policy as the real boundary,
  consistent with decision 2.*
- Should `deny_reason` be returned verbatim to the model? It helps self-correction but
  leaks policy structure. *Lean: yes for shape and cost rejections, coarse for policy
  rejections.*
- Catalog cache TTL versus schema drift: a stale catalog can reject valid queries. Invalidate
  on rejection, or accept staleness?
- Is `EXPLAIN USING JSON` genuinely free of warehouse cost in all Snowflake editions?
  Decision 3 leans on it; verify before publishing the claim.
- One principal per server instance for MVP. Where does per-user identity live when an
  agent acts on behalf of a human — the MCP session, or a token the tool call carries?
