# Demo assets

| File | Stage | Purpose |
|---|---|---|
| `roles.sql` | 4 | `warden_ro`: `USAGE` + `SELECT` only, `default_transaction_read_only = on`, no `CREATE` anywhere. The security boundary — the parser is not it. |
| `policy.example.yaml` | 8 | Table denial on `kyc_documents`, column masking on `customers.email`, `date_of_birth`, `account_number` |
| `audit_schema.sql` | 10 | Audit table DDL, applied to the *separate* audit database |
| `seed_postgres.sql` | 15 | Deterministic `generate_series` seed with a fixed `setseed` — ~10k customers, 25k accounts, 5M transactions, sized so the cost gate genuinely fires |
| `seed_snowflake.sql` | 15 | Same shape, clustered so micro-partition pruning is defeated by a poorly filtered query |
| `snowflake_setup.sql` | 14 | RBAC, native masking policies, resource monitor on a dedicated XSMALL warehouse |

CI runs against a small fixture; the large seed is for the manual demo and the one
dedicated cost-gate test. See plan.md §9.
