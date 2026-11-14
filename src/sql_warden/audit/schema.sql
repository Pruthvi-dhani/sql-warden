-- sql-warden's audit log: one row per request, allowed or not.
--
-- Applied at startup and safe to apply again: everything is IF NOT EXISTS. A column added
-- later must be added here as ALTER TABLE ... ADD COLUMN IF NOT EXISTS, so existing audit
-- databases pick it up too.

CREATE TABLE IF NOT EXISTS audit_events (
    id             uuid             PRIMARY KEY,
    ts             timestamptz      NOT NULL,
    session_id     text,
    identity       text,                          -- who: an API key's name, oidc:<subject>
    client         text,                          -- e.g. cli, or the MCP client's name
    profile        text,                          -- none if refused before it had one
    dry_run        boolean          NOT NULL,     -- check_query / sql-warden check
    sql            text             NOT NULL,     -- as sent
    executed_sql   text,                          -- as regenerated and run (or would run)
    rewrites       text[]           NOT NULL DEFAULT '{}',
    decision       text             NOT NULL
                   CHECK (decision IN ('allowed', 'refused', 'failed')),
    refused_by     text,                          -- the check that refused the query
    code           text,
    reason         text,
    error          text,                          -- why an allowed query failed to run
    cost_estimate  double precision,              -- the planner's estimate (Phase 4)
    rows_returned  integer,
    truncated      boolean,
    masked_columns text[]           NOT NULL DEFAULT '{}',
    duration_ms    double precision NOT NULL,
    trace          jsonb            NOT NULL      -- every check that ran, with its verdict
);

-- Added with authentication, for audit databases made before it: who the caller is, and no
-- profile at all for a request refused before it got one.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS identity text;
ALTER TABLE audit_events ALTER COLUMN profile DROP NOT NULL;

CREATE INDEX IF NOT EXISTS audit_events_ts ON audit_events (ts DESC);
CREATE INDEX IF NOT EXISTS audit_events_identity ON audit_events (identity, ts);
CREATE INDEX IF NOT EXISTS audit_events_session ON audit_events (session_id, ts);

-- Budgets, kept here so that every server recording to this log holds the same ones: a
-- session's or a caller's limit holds however many servers serve them.
--
-- What each session has used. Charged in one locked transaction per request; a session is
-- seeded from audit_events the first time it is charged, so one that began before this
-- table existed keeps what it had used.
CREATE TABLE IF NOT EXISTS session_usage (
    profile        text             NOT NULL,
    session_id     text             NOT NULL,
    queries        bigint           NOT NULL DEFAULT 0,
    total_cost     double precision NOT NULL DEFAULT 0,
    rows_returned  bigint           NOT NULL DEFAULT 0,
    refusals       bigint           NOT NULL DEFAULT 0,
    updated_at     timestamptz      NOT NULL DEFAULT now(),
    PRIMARY KEY (profile, session_id)
);

-- Every charge to a caller with a token, for budgets over a rolling window: their use is
-- the sum of what is younger than the window. Older rows are deleted as the caller is
-- charged again.
CREATE TABLE IF NOT EXISTS caller_charges (
    profile        text             NOT NULL,
    caller         text             NOT NULL,
    ts             timestamptz      NOT NULL DEFAULT now(),
    queries        integer          NOT NULL DEFAULT 0,
    total_cost     double precision NOT NULL DEFAULT 0,
    rows_returned  bigint           NOT NULL DEFAULT 0,
    refusals       integer          NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS caller_charges_by_caller ON caller_charges (profile, caller, ts);
