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
