# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A governed SQL gateway for AI agents, exposed over MCP. An agent submits SQL; the server
enforces every safety property server-side rather than asking for it in a prompt. Read-only
by construction — no writes, no NL-to-SQL.

The project is **built in numbered stages**. [plan.md](plan.md) is the design, threat model,
and decision log; [implementation-plan.md](implementation-plan.md) is the stage-by-stage build
order with a binary exit criterion per stage. Both are normative — code comments cite them by
section (`plan.md §4.3`, `decision 10`), and new code should keep doing that. Stages 0–1 are
complete and Stage 2 (`engines/base.py`, `catalog.py`) is partially landed; most modules named
in `plan.md` §3 do not exist yet.

## Commands

```bash
uv sync                                      # install (Python 3.12, pinned via .python-version)
docker compose up -d                         # target Postgres :5433, audit Postgres :5434

uv run ruff check && uv run ruff format --check
uv run mypy                                  # strict; files = ["src", "tests"] from pyproject
uv run pytest tests/unit tests/redteam -m "not integration and not snowflake"
uv run pytest -m integration                 # Postgres via Testcontainers (needs Docker)
uv run pytest -m snowflake                   # needs a live Snowflake account

uv run pytest tests/unit/test_config.py::test_the_example_loads   # single test
uv run pytest -k disclosure                                       # by name
```

The four local commands above are exactly what CI gates on, so running them is the whole
pre-push check. Copy `.env.example` to `.env` for the compose credentials.

## Architecture

**The admission pipeline** (`pipeline/`) is the spine: PARSE → SHAPE → RESOLVE → POLICY →
COST → EXECUTE → RECORD, each returning `Allow` or `Deny`. Stages 1–5 are pure and need no
execution, which is what makes the `explain_query` tool just "run the pipeline, stop before
EXECUTE". `pipeline/` is orchestration only.

**The engine seam** (`engines/base.py`) is where everything database-specific is *declared*;
`engines/postgres.py` and `engines/snowflake.py` implement it. The pipeline reads declarations
— `EnforcementModel`, `CostUnit`, guards — and never asks which engine it is talking to. **An
`if engine == "snowflake"` branch outside `engines/` is a design bug**: the capability belongs
on the `Engine` protocol instead. Config names engines through the `EngineName` enum rather
than string literals.

Three invariants the existing code exists to protect, each with tests that pin it:

- **Costs carry their unit.** There is no `max_cost: float` anywhere and there must not be.
  `CostEstimate.exceeds(threshold, unit)` raises `UnitMismatch` rather than comparing a
  Postgres planner cost to a byte count, and `SUPPORTED_COST_UNITS` is checked against config
  at load time so a threshold in a unit an engine cannot report fails at startup instead of
  silently never firing.
- **The audit database is not the target database.** `Config` rejects DSNs that address the
  same host/port/path (credentials ignored). Evidence must live outside the blast radius of
  the database being queried.
- **Denials disclose asymmetrically.** `Deny.detail` is always audited in full; only the
  client view is redacted. `DISCLOSURE` maps every `DenyReason` to `VERBATIM` (the query did
  something wrong — actionable) or `COARSE` (the server's configuration — not the agent's to
  enumerate). All coarse denials return one identical code and message, deliberately: differing
  text would let an agent map the policy by diffing rejections.

**Config** (`config.py`) is validated at load with cross-field `model_validator`s, expands
`${ENV_VAR}` references (an unset variable is fatal), and raises `ConfigError` for everything —
callers should never have to catch `ValidationError` too. `demo/config.example.yaml` is loaded
by a test so it cannot drift from the schema.

`server.py` is the **only** module permitted to import from `mcp`. The dependency is pinned
`<2` because the 2026-07-28 spec rewrites the low-level `Server` interface; confining it keeps
that migration to one file.

## Conventions

- Everything inherits `FrozenModel` (`extra="forbid"`, `frozen=True`). A limit that can be
  raised at runtime is not a limit; an unrecognised config key is an error, not a shrug.
- `StrEnum` for anything that reaches YAML, JSON, or an audit row.
- Enum-total maps (`DISCLOSURE`, `SUPPORTED_COST_UNITS`) are tested with `@pytest.mark.parametrize`
  over the enum plus a set-equality check, so adding a member without an entry fails immediately.
  Keep that pattern when adding one.
- Every new `DenyReason` arrives with a test that provokes it.
- `filterwarnings = ["error"]` and `--strict-markers`: a deprecation is a failure.
- No `# type: ignore` without a comment naming the reason. `mypy --strict` and `ruff check`
  (which includes the Bandit `S` rules) are gates.
- Comments here carry design rationale, not narration — the prose explains *why a weaker
  alternative was rejected*. Match that when touching these files.
- New integration tests must be marked `@pytest.mark.integration` or `@pytest.mark.snowflake`;
  the CI split is a marker selector, not separate suites.
- Red-team corpora in `tests/redteam/` are parser-level, need no database, and gate every push.
- `plan.md` and `implementation-plan.md` are excluded from ruff formatting — their Python
  snippets are illustrative design, not code.
