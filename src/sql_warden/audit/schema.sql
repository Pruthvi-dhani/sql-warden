-- sql-warden's audit log: one row per request, allowed or not.
--
-- Applied by `sql-warden audit init`, and at startup by a server whose role owns the tables
-- (or finds none yet); safe to apply again: everything is IF NOT EXISTS. A column added
-- later must be added here as ALTER TABLE ... ADD COLUMN IF NOT EXISTS, so existing audit
-- databases pick it up too, and to the columns PostgresAuditSink checks for (sink.py).

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

-- Every `sql-warden audit prune`: who removed what, recorded in the same transaction as the
-- removal. The role that prunes may add rows here and nothing more, so what it removed
-- stays on record.
CREATE TABLE IF NOT EXISTS audit_prunes (
    ts              timestamptz      NOT NULL DEFAULT now(),
    pruned_by       text             NOT NULL DEFAULT session_user,
    older_than      timestamptz      NOT NULL,  -- events recorded before this were removed
    events          bigint           NOT NULL,
    sessions        bigint           NOT NULL,  -- budget rows of sessions idle since then
    caller_charges  bigint           NOT NULL
);

-- What each of the roles from deploy/audit_roles.sql may do, for the ones that exist. The
-- writer (the server) adds records and reads them back for budgets, and keeps the budget
-- tables, but can't change or remove a record. The pruner removes old rows and records
-- that it did. The reader reads, for `audit tail`, `show` and `export`.
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'sql_warden_writer') THEN
        GRANT SELECT, INSERT ON audit_events TO sql_warden_writer;
        GRANT SELECT, INSERT, UPDATE ON session_usage TO sql_warden_writer;
        GRANT SELECT, INSERT, DELETE ON caller_charges TO sql_warden_writer;
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'sql_warden_pruner') THEN
        GRANT SELECT (ts), DELETE ON audit_events TO sql_warden_pruner;
        GRANT SELECT (updated_at), DELETE ON session_usage TO sql_warden_pruner;
        GRANT SELECT (ts), DELETE ON caller_charges TO sql_warden_pruner;
        GRANT INSERT ON audit_prunes TO sql_warden_pruner;
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'sql_warden_reader') THEN
        GRANT SELECT ON audit_events, audit_prunes TO sql_warden_reader;
    END IF;
END
$$;
