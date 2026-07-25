# sql-warden

A **governed SQL gateway for AI agents, exposed over MCP**. It lets an agent query a real
database and enforces every safety property *server-side*, rather than requesting it in a
prompt.

Every query passes an admission pipeline — parse, shape, resolve, policy, cost, execute,
record — and any stage can reject it with a typed reason. AST-level validation via an
allowlist, a pre-execution cost gate using the engine's own planner, column masking and
table denial from a declarative policy, per-session budgets, and a full audit trail written
to a database separate from the one being queried.

Two engines ship: **PostgreSQL** (OLTP) and **Snowflake** (warehouse), chosen because they
are dissimilar enough that the engine abstraction has to be real.

> **Status: under construction.** Stage 0 (scaffolding) is complete. See
> [implementation-plan.md](implementation-plan.md) for the stage-by-stage build order and
> [plan.md](plan.md) for the full design, threat model, and decision log.
>
> The architecture diagram, tool surface, engine comparison table, decision log, threat
> model, and CI split land here in Stage 15.

## Development

Requires [uv](https://docs.astral.sh/uv/) and Docker.

```bash
uv sync                  # install dependencies (Python 3.12, pinned via .python-version)
docker compose up -d     # target Postgres on :5433, audit Postgres on :5434
```

### Tests

```bash
uv run ruff check && uv run mypy       # lint and typecheck (mypy --strict)
uv run pytest tests/unit               # no database required
uv run pytest -m integration           # Postgres via Testcontainers
uv run pytest -m snowflake             # requires a live Snowflake account
```

The split is deliberate and mirrors CI: policy correctness is unit-testable and gates every
push, Postgres is hermetically testable via Testcontainers so it does too, and Snowflake
enforcement needs a live account so it runs on demand and weekly.

## Non-goals

**Prompt injection is out of scope, deliberately.** Data returned from a database can
contain adversarial instructions. That is a client-side trust problem and cannot be solved
at this layer. Returned data is marked `content_trust: untrusted` and the threat is
documented rather than papered over.

No write access of any kind. No natural-language-to-SQL — the agent writes the SQL, this
server governs it.

## License

MIT
