# sql-warden — Implementation Plan

## Context

[plan.md](plan.md) defines *what* sql-warden is: a governed SQL gateway for AI agents over
MCP, with a seven-stage admission pipeline, two dissimilar engines (Postgres, Snowflake),
and server-side enforcement of every safety property. What it does not define is a build
order.

This document is the stage-by-stage build order `plan.md` §11 defers to: every stage is a
few hours of work, ends with a green test suite, and leaves the project in a coherent
state. The intended outcome is that the project can be built incrementally without a
big-bang integration at the end, and that the red-team corpus and conformance suite grow
alongside the code rather than being retrofitted.

**Decisions taken before writing this** (from `plan.md` §12 and clarification):
- A live Snowflake account is available, so M5 is genuinely verifiable and the "seam is
  proven" claim is earned rather than asserted.
- Stages are small and numerous (16), not the seven coarse milestones.
- Budget checks split: query-count and fingerprint rate-limit run immediately after PARSE;
  the cumulative-cost check folds into COST. The pipeline stays seven stages.

---

## Findings that change the design

Three things verified before planning, each of which alters a stage.

### 1. The MCP protocol is mid-migration, and it lands during this build

The MCP Python SDK's stable line is **1.28.1**. A **v2.0.0** is targeted for **27 July 2026**
alongside the 2026-07-28 spec, and it is not a cosmetic bump: the protocol moves from
**stateful bidirectional to stateless request/response**. The low-level `Server` interface
changes (handlers become constructor parameters, not decorators), and `ServerSession`
becomes a thin proxy over a new dispatcher pipeline. The maintainers state v1.x remains
recommended for production and is in maintenance mode.

This is not just a pinning question. `plan.md` §4.8 scopes budgets **per session**, and §12
asks whether per-user identity lives in "the MCP session". If the protocol becomes
stateless, *the MCP session stops being a durable anchor for either*.

**Consequence for the plan:**
- Pin `mcp>=1.28,<2` for the MVP. Do not adopt v2 mid-build.
- Confine every MCP-SDK import to `server.py`. No SDK type may appear in `pipeline/`,
  `engines/`, or `budget.py`. A v2 migration must be one file.
- **Budgets key off a `principal` + `session_id` that sql-warden owns**, derived from
  config and an explicit transport/tool-level identifier — never off SDK session object
  identity. This is designed in at Stage 11, not patched later.

### 2. Snowflake `EXPLAIN` is cheaper than "free", and the estimate is warehouse-relative

Confirmed: `EXPLAIN` compiles without executing and **does not require a running
warehouse**, so it consumes no warehouse compute credits. Two caveats `plan.md` §4.5 does
not capture:

- It **does** consume **Cloud Services credits**, like other metadata operations. The
  README claim should be "no warehouse compute", not "free".
- **The plan depends on warehouse size.** Run outside a warehouse context, Snowflake builds
  the plan against an **XSMALL**. A cost threshold calibrated under one warehouse silently
  means something different under another.

**Consequence:** `SnowflakeEngine` must pin an explicit warehouse context for estimation and
record it on the `CostEstimate`, so thresholds are reproducible. Stage 14 covers this.

### 3. sqlglot's `qualify()` is most of the RESOLVE stage — and star expansion is a security control

Verified signature:

```python
qualify(expression, dialect=None, db=None, catalog=None, schema=None,
        expand_alias_refs=True, expand_stars=True, infer_schema=None,
        isolate_tables=False, qualify_columns=True, allow_partial_qualification=False,
        validate_qualify_columns=True, quote_identifiers=True, identify=True, ...)
```

With a `MappingSchema` built from our catalog and `validate_qualify_columns=True`,
unresolvable columns raise `sqlglot.errors.OptimizeError` — that is the RESOLVE rejection,
for free, from a well-tested library rather than a hand-rolled walker.

The load-bearing insight: **`expand_stars=True` must run before the POLICY stage.**
`SELECT * FROM customers` contains no `email` node to rewrite. If policy runs on an
unexpanded star, masking silently does nothing and the demo leaks exactly the column the
project exists to protect. Star expansion is therefore a security control, not a
convenience, and gets a dedicated test.

The same property solves most of §12's laundering problem: after `qualify()`, every column
reference is fully qualified to its source relation, so rewriting `exp.Column` nodes
**in place** naturally handles `upper(email)`, `email AS e`, and `substr(email,1,3)` — the
Column node is replaced inside whatever expression wraps it. CTE projection is the residual
hard case, handled via `sqlglot.optimizer.scope.traverse_scope` to walk each CTE's
projections back to their source columns (Stage 9).

---

## Cross-cutting rules

Applied from Stage 0 and enforced in CI:

1. `ruff check` and `mypy --strict` are gates, not suggestions. No `# type: ignore` without
   a comment naming the reason.
2. **No engine name appears outside `engines/`.** A design principle held in review, not a
   mechanical gate. If a stage finds itself branching on which engine is in use, the
   capability belongs on the `Engine` protocol — declared by the engine, read by the
   pipeline. Config refers to engines through an `EngineName` enum exported from
   `engines/` rather than by writing the literal strings.
3. Every stage ends green. No stage leaves a failing test for the next one to fix.
4. Every new `DenyReason` arrives with a test that provokes it.
5. Integration tests are marked (`@pytest.mark.integration`, `@pytest.mark.snowflake`) so
   the CI split in `plan.md` §8 is a selector, not a separate suite.

---

## Stages

Each stage lists what it builds, what it tests, and a binary exit criterion.

### Stage 0 — Toolchain and scaffolding

Local Python is **3.10.11** and the project needs **3.12** (`StrEnum` in §4.3 is 3.11+).
`uv` is not installed. Both are resolved here.

- Install `uv`; `uv python install 3.12`; pin via `.python-version`.
- `pyproject.toml`, src layout, `requires-python = ">=3.12"`.
- Deps pinned: `sqlglot`, `pydantic>=2`, `psycopg[binary,pool]>=3`, `mcp>=1.28,<2`,
  `prometheus-client`, `pyyaml`. Dev: `pytest`, `pytest-asyncio`, `testcontainers`,
  `ruff`, `mypy`.
- `docker-compose.yml`: **two** Postgres services — `target` and `audit`, separate
  credentials, no shared role.
- GitHub Actions: lint, typecheck, unit, integration jobs.

**Tests:** one trivial unit test plus a Testcontainers smoke test that starts Postgres 16
and executes `SELECT 1`.

**Exit:** `uv run ruff check`, `uv run mypy --strict src`, `uv run pytest` all green locally
and in CI. `docker compose up` yields two reachable, independent databases.

---

### Stage 1 — Decisions, deny reasons, config

Files: `pipeline/decisions.py`, `config.py`, `engines/base.py` (partial)

- `EngineName` as a `StrEnum` in `engines/base.py` — just the enum, the rest of the
  protocol lands in Stage 2. It has to exist here because `config.py` types `cost_gate`
  keys against it, which is what turns a typo'd `postgrez:` section into a load-time
  error rather than a silently absent cost gate.
- `Stage` and `DenyReason` as `StrEnum`. `Decision = Allow | Deny(reason, message, stage)`.
- `DenyReason` carries a **disclosure level** (`VERBATIM` | `COARSE`), resolving §12's
  second open question in the type system rather than at call sites: shape and cost
  rejections are verbatim so the agent can self-correct; policy rejections are coarse so
  the policy structure does not leak.
- Pydantic v2 config model for `plan.md` §5, with `cost_gate` nested per engine.

**Tests (unit, no DB):** §5's YAML round-trips; a config whose `cost_gate` unit disagrees
with the selected engine's native unit is a **load-time** error, not a runtime surprise;
every `DenyReason` has a disclosure level (parametrised over the enum, so a new reason
without one fails); coarse reasons never emit the raw message.

**Exit:** config example loads; disclosure-level coverage test passes over all reasons.

---

### Stage 2 — Engine protocol and catalog model (no I/O)

Files: `engines/base.py`, `catalog.py`

- `CostUnit`, `CostEstimate`, `Enforced`, `EnforcementModel`, `Guard`, `Session`, `Engine`
  Protocol exactly as `plan.md` §4.3, joining the `EngineName` enum added in Stage 1.
- `engines/registry.py`: `EngineName -> factory` dict and `build_engine(cfg)`. This is the
  single site where engine identity is consulted, once at startup — the Strategy selection
  point. Nothing downstream branches on which engine is in use.
- `CostEstimate` gains an optional `context: str | None` field for finding #2 (which
  warehouse the estimate is relative to).
- `Catalog` / `Table` / `Column` dataclasses and `Catalog.to_sqlglot_schema() -> MappingSchema`.
- TTL cache with an **injected clock**, so expiry is tested without sleeping.

**Tests (unit):** TTL expiry and refresh against a fake clock; `to_sqlglot_schema` mapping
including quoting and case handling; `EnforcementModel` JSON shape matches the envelope in
§4.7; a `Protocol` conformance assertion that fails to typecheck if an engine is incomplete.

**Exit:** `mypy --strict` clean with zero engine implementations. No `Any` in the protocol.

---

### Stage 3 — PARSE and SHAPE + shared red-team corpus

Files: `pipeline/stages.py` (PARSE, SHAPE), `tests/redteam/shared.sql`

- Parse in the engine's dialect. Parse failure → `DenyReason.PARSE_ERROR`. Never fall back
  to sending it.
- Exactly one statement (`sqlglot.parse` returning >1 → deny; this kills stacked statements).
- **Allowlist** of permitted node types. Top level must be `Select`, or a `With` whose
  final expression is a `Select`. Everything else denied by absence.
- `Guard` runner hook (engine guards are empty until Stage 5).

**Tests:** unit — allowlist completeness, parametrised so that any node type *not* in the
allowlist is rejected (catches a future sqlglot upgrade adding node types); casing, unicode
escapes, and comment obfuscation do not change the verdict.
Red team — `shared.sql` green: stacked statements, `WITH x AS (DELETE ... RETURNING *) SELECT * FROM x`,
comment-smuggled payloads, recursive-CTE bombs. Each line asserts both *rejection* and the
*expected `DenyReason`*.
Plus a **corpus-loaded assertion**: the parsed corpus must be non-empty and every declared
file must exist. An empty corpus collects zero tests and reports a green tick, which is the
characteristic silent failure of file-driven suites — the most valuable security signal in
the repo must not be able to disappear quietly.

**Exit:** shared corpus fully green. No database involved.

---

### Stage 4 — Postgres: connection, introspection, read-only session

Files: `engines/postgres.py`, `tests/conftest.py`, `demo/roles.sql`

- Async psycopg3 pool. `introspect()` from `information_schema.columns`,
  `pg_class.reltuples`, `pg_constraint`.
- `readonly_session()`: `BEGIN READ ONLY` + `SET LOCAL statement_timeout`.
- `warden_ro` role: `USAGE` + `SELECT` only, `default_transaction_read_only = on`, no
  `CREATE` anywhere.
- Small deterministic fixture schema (the §9 tables at CI scale).

**Tests:** integration — introspected catalog matches the fixture (columns, types, PK/FK,
row estimate present); **first defence-in-depth test**: bypass the pipeline entirely and
fire `INSERT` / `UPDATE` / `CREATE TABLE` / `DROP` directly through the read-only session,
asserting the *engine* refuses each. This makes `plan.md` decision 2 demonstrated on the
same day the engine appears.

**Exit:** Testcontainers Postgres green in CI; raw DML refused by the role.

---

### Stage 5 — RESOLVE + Postgres guards

Files: `pipeline/stages.py` (RESOLVE), `engines/postgres.py` (guards), `tests/redteam/postgres.sql`

- RESOLVE calls `qualify(ast, schema=catalog.to_sqlglot_schema(), dialect=...,
  validate_qualify_columns=True, expand_stars=True)`, catching `OptimizeError` →
  `DenyReason.UNKNOWN_OBJECT`.
- Schema allowlist enforced on every resolved table.
- Postgres `Guard`s wired into SHAPE: `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`,
  `lo_import`/`lo_export`, `COPY`, `dblink`, `postgres_fdw`, `pg_sleep`, `DO`,
  `CREATE FUNCTION`, set-returning function abuse.

**Tests:** unit against a static catalog — unknown column, unknown table, out-of-allowlist
schema, CTE-scoped resolution, and **`SELECT *` expands to explicit qualified columns**
(the finding-#3 control, asserted directly).
Red team — `postgres.sql` green with correct deny reasons.
Integration — resolve against the live introspected catalog, proving the mapping is real.

**Exit:** both corpora green; star expansion verified; cross-schema read denied.

---

### Stage 6 — Postgres cost gate

Files: `engines/postgres.py` (`estimate`), `pipeline/stages.py` (COST)

- `EXPLAIN (FORMAT JSON)` → `Plan."Total Cost"`, `Plan Rows` → `CostEstimate(PLANNER_COST,
  is_pre_execution=True)`.
- COST compares against the engine's configured threshold **in its own unit**; a mismatch is
  a programming error and raises rather than silently coercing.

**Tests:** integration — a selective query passes; a deliberately expensive scan over the
large-ish fixture is rejected with `DenyReason.COST_EXCEEDED`; `EXPLAIN` is verified not to
execute (row counters unchanged).
Unit — unit-mismatch raises; threshold boundary is inclusive/exclusive as documented.

**Exit:** cost gate fires before execution on the demo table.

---

### Stage 7 — EXECUTE, row limit, envelope, truncation

Files: `engines/postgres.py` (`apply_row_limit`), `pipeline/stages.py` (EXECUTE), `envelope.py`

- `apply_row_limit` injects `LIMIT n+1` at the AST level — fetching one extra row is how
  `truncated` is known rather than guessed.
- Execute inside the read-only session with the statement timeout.
- Build the §4.7 envelope: `row_count`, `truncated`, `limit_applied`, `cost`, `enforcement`,
  `content_trust: "untrusted"`.

**Tests:** integration — limit applied; `truncated=true` when more rows exist and `false` at
exactly the limit (the off-by-one that matters, since a wrong answer here makes the model
state a false fact); an existing user `LIMIT` larger than the cap is clamped; statement
timeout fires and surfaces as a typed deny, not a raw driver exception.

**Exit:** envelope complete except policy and audit fields.

---

### Stage 8 — Policy model

Files: `policy/model.py`, `demo/policy.example.yaml`

- Pydantic model for §4.6: `allowed_schemas`, table `deny`, column `mask` with
  `sha256` / `fixed` / `last4` strategies.
- Table denial short-circuits at the POLICY stage with a **coarse** reason (Stage 1).

**Tests (unit):** policy parses; unknown strategy rejected at load; a policy naming a
non-existent table is a load-time warning (drift, not silent no-op); denied tables are
omitted from `list_tables` and rejected by RESOLVE.

**Exit:** `kyc_documents` denial provable without any masking code existing.

---

### Stage 9 — Masking rewrite and the laundering corpus

Files: `policy/rewrite.py`

The hardest correctness work in the project, and it gets its own stage.

- Rewrite operates **only on a post-`qualify()` AST** — enforced by an assertion, since
  rewriting an unqualified tree is unsound.
- Replace `exp.Column` nodes in place via `traverse_scope`, so wrapping expressions,
  aliases, and function calls are handled structurally.
- CTE projections walked back to source columns.
- Emit the `redactions` list into the envelope.

**Tests (unit, the §12 corpus):** `SELECT email`, `SELECT upper(email)`, `SELECT email AS e`,
`SELECT substr(email,1,3)`, `SELECT * FROM customers`, a CTE projecting `email` then
selected from, a subquery, a `UNION` arm, `ORDER BY email`, `WHERE email = '...'`, and a
join aliasing the table. Each asserts the raw value is unreachable and `redactions` names
the column.
Integration — the masked value returned by the database genuinely differs from the stored
value, and `warden_ro` **lacks the column `GRANT`** so the rewrite's failure mode is denial,
not leakage (decision 2 applied to masking).

**Exit:** every laundering case masked; column grant backstop verified.

---

### Stage 10 — Audit store and writer

Files: `audit.py`, `demo/audit_schema.sql`

- Separate audit database (already in compose from Stage 0). The audit role has **no grants**
  on the target, and the target role has none on audit — asserted by test.
- One row per attempt, allowed or denied, with the §4.9 columns.
- **Audit failure is fail-closed.** If the audit write fails, the query is denied. An
  attacker who can blind the log must not thereby gain a silent channel. This is a decision
  `plan.md` does not state; it belongs in the README decision log.

**Tests:** integration — a denial at *each* stage produces exactly one row with the right
`stage` and `deny_reason` (parametrised over the pipeline, so a new stage without auditing
fails); allowed queries record cost, rows, duration, redactions, enforcement; the audit role
cannot read the target and vice versa; audit DB down → query denied, not silently executed.

**Exit:** the two-database separation is a test, not a claim.

---

### Stage 11 — Budgets and fingerprinting

Files: `budget.py`

- Fingerprint = qualified AST with literals normalised out, rendered via `.sql()`. Stable
  across whitespace, casing, and rolling literals.
- Split placement as decided: count + fingerprint rate limit immediately after PARSE;
  cumulative cost inside COST.
- `principal` and `session_id` are **owned by sql-warden**, not by the MCP SDK (finding #1).

**Tests:** unit — fingerprint identical across literal/whitespace/case variation and
*different* across structural change; budget arithmetic; rate-limit window boundaries with a
fake clock.
Integration — the 51st query in a session is denied and audited with the budget stage;
rate-limited repeats are denied before any `EXPLAIN` round-trip is spent (asserted by
counting engine calls — this is the whole point of the placement decision).

**Exit:** budget denials audited; no engine round-trip on a rate-limited query.

---

### Stage 12 — MCP surface

Files: `server.py`

- The five tools from §4.1. `explain_query` runs stages 1–5 and stops.
- Tool descriptions written **for a model**: explicitly instructing disclosure of
  `truncated`, and that returned rows are untrusted content.
- All `mcp` imports confined to this file, so a v2 migration stays local (finding #1).

**Tests:** integration — an in-process MCP client drives all five tools; `describe_table`
reports policy-restricted columns; `list_schemas`/`list_tables` omit what policy denies;
**`explain_query` provably does not execute** (asserted via engine call counting and the
absence of an EXECUTE audit row); a denied query returns a coarse reason for policy and a
verbatim one for shape.

**Exit:** end-to-end transcript captured, including a rejected malicious query beside its
audit row.

---

### Stage 13 — Conformance suite extraction

Files: `tests/conformance/`

Refactor, no new features. Lift the Postgres integration tests into **one** abstract suite
parametrised over `Engine` implementations: introspection shape, read-only enforcement, cost
estimation, masking, row limits, timeout, audit record shape.

**Exit:** the extracted suite is green on Postgres and the Postgres-specific integration
tests it replaced are deleted, not duplicated. The parametrisation currently yields one
engine.

---

### Stage 14 — Snowflake engine

Files: `engines/snowflake.py`, `demo/snowflake_setup.sql`

- `EXPLAIN USING JSON` → partitions and bytes assigned. **Pin an explicit warehouse for
  estimation and record it on `CostEstimate.context`** (finding #2).
- `EnforcementModel`: `masking=NATIVE` — the AST rewrite is *skipped*, native column masking
  policies are the enforcement. `readonly=NATIVE` via RBAC only, no read-only transaction.
- `STATEMENT_TIMEOUT_IN_SECONDS`; resource monitor on a dedicated XSMALL warehouse.
- `QUERY_TAG` carrying the audit id.
- Snowflake guards: `COPY INTO <location>`, `CREATE STAGE`, `PUT`/`GET`, external functions
  and access integrations, Java/Python/Scala UDFs, stored procedures, `CREATE TASK`,
  cross-database/share access, `SYSTEM$*`, and `RESULT_SCAN`.

**Tests:** red team — `tests/redteam/snowflake.sql` green.
Integration (`@pytest.mark.snowflake`, live account) — native masking applies to a query
issued *outside* sql-warden (which is the whole argument for `NATIVE`); `QUERY_TAG`
reconciles the local audit row against `ACCOUNT_USAGE.QUERY_HISTORY`, turning audit
completeness into a proof; `EXPLAIN` confirmed not to require a running warehouse.

**Exit:** **the conformance suite from Stage 13 is green against both engines, unmodified.**
This is the milestone that proves the seam; if it required editing the suite, the
abstraction failed and that is the signal to fix `Engine`, not the test.

---

### Stage 15 — Metrics, demo seed, README

- Prometheus counters/histograms labelled by stage and deny reason.
- Large deterministic seed (`generate_series` + fixed `setseed`): ~10k customers, 25k
  accounts, 5M transactions, sized so the cost gate fires. Snowflake variant clustered so
  micro-partition pruning is genuinely defeated by a bad filter.
- README: architecture diagram, tool surface, pipeline, engine comparison table, decision
  log (§6 **plus** audit fail-closed and the MCP-v2 isolation rationale), threat model, and
  the CI split stated openly.

**Exit:** `docker compose up` → seeded stack → transcript reproducing the cost-gate
rejection and the masked query.

---

## Verification

Per stage:
```
uv run ruff check && uv run mypy --strict src
uv run pytest tests/unit                       # every stage, no DB
uv run pytest -m integration                   # Stage 4 onward, Testcontainers
uv run pytest -m snowflake                     # Stage 14 onward, live account
```

End-to-end once Stage 15 lands:
1. `docker compose up -d` → target + audit Postgres, seeded.
2. Run the server against `demo/policy.example.yaml`; drive it with a real MCP client.
3. `describe_table('analytics','customers')` → `email` shown as masked.
4. `run_query('SELECT * FROM analytics.transactions')` → `COST_EXCEEDED`, nothing executed.
5. `run_query('SELECT upper(email) FROM analytics.customers')` → masked values, `redactions`
   populated, `enforcement.masking == "server"`.
6. `run_query('SELECT * FROM analytics.kyc_documents')` → coarse policy denial.
7. Query the **audit** database: four rows, correct stages and reasons, none of it written
   to the target.
8. Repoint config at Snowflake, repeat 3–7; confirm `enforcement.masking == "native"` and
   reconcile via `QUERY_TAG`.

---

## Stage-to-milestone mapping

| `plan.md` §11 milestone | Stages |
|---|---|
| M0 — Scaffolding | 0 |
| M1 — Pipeline skeleton + Postgres engine | 1, 2, 3, 4, 5 |
| M2 — Enforcement | 6, 7 |
| M3 — Policy + audit | 8, 9, 10 |
| M4 — MCP surface | 12 |
| M5 — Snowflake engine | 13, 14 |
| M6 — Budgets, metrics, docs | 11, 15 |

Budgets (Stage 11) move earlier than M6 because the MCP surface needs a session identity to
exist before it can pass one in.

---

## Sources

- [EXPLAIN | Snowflake Documentation](https://docs.snowflake.com/en/sql-reference/sql/explain)
- [MCP Python SDK — PyPI](https://pypi.org/project/mcp/)
- [Releases · modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk/releases)
- [Beta SDKs for the 2026-07-28 MCP Spec Release Candidate](https://blog.modelcontextprotocol.io/posts/sdk-betas-2026-07-28/)
- [sqlglot qualify.py](https://github.com/tobymao/sqlglot/blob/main/sqlglot/optimizer/qualify.py)
