# Red-team corpora

Adversarial SQL, every line of which must be **rejected**, asserted against both the
expected outcome and the expected `DenyReason`.

These are parser-level assertions and need no database, so they run in the `unit` CI job
and gate every push. See plan.md §7.

| File | Stage | Contents |
|---|---|---|
| `shared.sql` | 3 | Engine-agnostic: stacked statements, DML smuggled inside CTEs, comment obfuscation, unicode and casing evasion, cross-schema reads, recursive-CTE bombs, masked-column laundering |
| `postgres.sql` | 5 | `COPY ... TO PROGRAM`, `pg_read_file`, `lo_export`, `dblink`, `pg_sleep`, `DO` blocks |
| `snowflake.sql` | 14 | `COPY INTO` an external stage, `CREATE STAGE` + `GET`, external functions and access integrations, Java/Python UDFs, `RESULT_SCAN`, cross-database shares, `SYSTEM$` functions |

Directory tracked from Stage 0 so the CI job that runs it cannot silently reference a
path that does not exist.
