-- The roles of a hardened audit database. Run once, as its administrator (a superuser, or a
-- role with CREATEROLE that owns the database), in the audit database:
--
--   psql "$AUDIT_ADMIN_DSN" -f deploy/audit_roles.sql
--
-- Safe to run again. It makes four group roles, none of which can log in:
--
--   sql_warden_owner    owns the tables, and alone may change them
--   sql_warden_writer   the server's: adds records and reads them back for budgets, keeps
--                       the budget tables, and can't change or remove a record
--   sql_warden_pruner   the retention job's: removes old rows, and records that it did
--   sql_warden_reader   for people and exports: reads the records
--
-- Then the tables, made by the owner (`audit init` also grants each role what it may do):
--
--   sql-warden audit init --owner sql_warden_owner --audit-dsn "$AUDIT_ADMIN_DSN"
--
-- And a login for each that is used, given its group. With a secrets manager, its password
-- is what the manager rotates:
--
--   CREATE ROLE warden LOGIN PASSWORD '...' IN ROLE sql_warden_writer;
--   CREATE ROLE audit_retention LOGIN PASSWORD '...' IN ROLE sql_warden_pruner;
--   CREATE ROLE audit_analyst LOGIN PASSWORD '...' IN ROLE sql_warden_reader;
--
-- Never make the server's login a member of sql_warden_owner, nor give it more than its
-- group: `sql-warden config validate --live` and every server start check that it can only
-- add records, and with audit.append_only a server refuses to start otherwise.

DO $$
DECLARE
    name text;
BEGIN
    FOREACH name IN ARRAY ARRAY[
        'sql_warden_owner', 'sql_warden_writer', 'sql_warden_pruner', 'sql_warden_reader'
    ] LOOP
        IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = name) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', name);
        END IF;
    END LOOP;
END
$$;

-- The owner makes the tables in public; nobody else makes anything there. (Before
-- Postgres 15, every role could create tables in public.)
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO sql_warden_owner;
GRANT USAGE ON SCHEMA public TO sql_warden_writer, sql_warden_pruner, sql_warden_reader;

-- Logins connect; that is all a database grants them.
DO $$
BEGIN
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO sql_warden_owner, sql_warden_writer, '
        'sql_warden_pruner, sql_warden_reader',
        current_database()
    );
END
$$;
