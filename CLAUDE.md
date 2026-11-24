# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

sql-warden is a governed SQL gateway: an MCP server (and `sql-warden` CLI) that lets an AI agent
query a real database (Postgres or Snowflake) while the server, not the prompt, enforces a policy
from `warden.yaml`.

## Commands

Python 3.12, managed with uv (`uv sync` installs everything, dev tools included, into `.venv`).

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy                                   # strict, covers src/ and tests/
uv run pytest -m "not integration and not snowflake"   # unit tests (what CI's unit job runs)
uv run pytest -m "integration and not snowflake"       # Postgres via Testcontainers; needs Docker
uv run pytest tests/unit/test_access_check.py::test_name   # one test
uv run --with 'fakesnow==0.12.1' --with 'snowflake-connector-python<5' pytest tests/fakesnow
SNOWFLAKE_DSN='snowflake://...' uv run pytest -m snowflake  # live Snowflake account only
```

- fakesnow is deliberately not a project dependency (it pins an older sqlglot and connector < 5);
  always layer it with `--with` as above.
- CI (`.github/workflows/ci.yml`) runs `uv sync --locked`, so `uv.lock` must be kept current.
- Integration tests start their own throwaway containers. Tests are blocked from reaching the
  demo stack's ports (`no_demo_stack` in `tests/unit/conftest.py`); use the `engines` /
  `audit_sinks` fixtures instead of default DSNs.

Running it by hand needs the demo stack:

```bash
docker compose -f dev/docker-compose.yml up -d   # warehouse :5433, audit DB :5434
cp warden.example.yaml warden.yaml
uv run sql-warden check "select id, name from products"   # dry run, shows each check's verdict
uv run sql-warden query "..." --profile support
uv run sql-warden serve [--transport http]
uv run python -m tests.portal                    # browser MCP client at :8765
uvx --with mkdocs-material mkdocs build --strict # docs site (site/ is build output)
```

## Architecture

The request path lives in `Warden` (`src/sql_warden/warden.py`), one instance per profile:
budget gate → parse → shape → access → masking → cost → budget reservation → execute → mask
results → audit record. `docs/how-it-works.md` is the authoritative walkthrough; read it before
changing or adding a check.

Invariants that span many files:

- **What runs is what was checked.** SQL is parsed once by sqlglot (`pipeline/parse.py`); every
  check reads `ctx.statements` from the shared `CheckContext`, and the SQL sent to the database is
  regenerated from that tree. The raw text never reaches the database. Checks that mutate the tree
  (added `LIMIT`, schema-pinned tables) must append a note to `ctx.rewrites`.
- **Checks** implement the `Check` protocol in `pipeline/base.py` (`name`, `run(ctx) -> Refusal |
  None`). The `Pipeline` short-circuits on the first refusal and converts exceptions into
  `INTERNAL_ERROR`. Not every check is in every pipeline: access/masking/budget are only added when
  the profile configures them.
- **Fail closed.** Every failure path is a structured refusal with a `RefusalCode` (`models.py`),
  e.g. `CATALOG_UNAVAILABLE`, `COST_UNAVAILABLE`, `AUDIT_UNAVAILABLE`. Nothing is answered without
  an audit record; if the audit write fails after execution, rows are withheld. Refusal reasons
  must not reveal whether a forbidden table exists.
- **EXPLAIN only after shape/access/masking pass**, so unvetted SQL never reaches the planner.
- **Engines** (`engines/base.py`) expose `execute`, `explain`, `tables`, `role` plus `max_rows`.
  Checks and `Warden` only use this protocol, so unit tests run on `FakeEngine`
  (`tests/unit/conftest.py`). Postgres cost is planner cost; Snowflake cost is bytes scanned.
- **Defence in depth:** read-only role + read-only transaction + statement timeout + row cap;
  `startup.py` refuses to serve as a role that can write.
- **Audit DB is always Postgres**, separate from the warehouse, whatever the engine. Session
  budgets (`sessions.py`, Postgres store under `audit/`) live there too, which is how they're
  shared across replicas. Connection pools are in `pools.py` and `audit/connections.py`.
- **Profiles** (`config.py`, `profiles.py`) are chosen by the deployer (`--profile`) or by the
  caller's token over HTTP (`auth.py`); the agent can never pick one. MCP tools take only SQL.

### Dialects

Checks read SQL in the warehouse's dialect. Unit tests that take the `dialect` fixture run once
for Postgres and once for Snowflake (`tests/unit/dialects.py`): write them Postgres-style with
lower-case names and use the `dialects` helpers (`stored`, `catalog`, ...) so Snowflake's
upper-case names work. Mark Postgres-only syntax tests `@pytest.mark.postgres_only`.

## Working conventions

- `docs/plan.md` is the roadmap. Each plan point is one commit shipping code plus tests, leaving
  ruff, mypy strict and pytest green; finished points are marked `✅ done` with their commit hash.
- User-facing behaviour is documented under `docs/` (and every policy key in
  `warden.example.yaml`); keep those in step with code changes.
