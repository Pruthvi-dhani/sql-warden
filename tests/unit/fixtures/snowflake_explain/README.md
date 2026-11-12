# Snowflake EXPLAIN USING JSON plans

What `SnowflakeEngine.explain()` has to read, since fakesnow has no planner.

- `docs_join.json` is the example in Snowflake's documentation for `EXPLAIN`
  (`SELECT Z1.ID, Z2.ID FROM Z1, Z2 WHERE Z2.ID = Z1.ID`), key for key.
- The others are written by hand in that shape, with sizes in the range of the demo data:
  they are not recordings from an account. `tests/snowflake/` checks the shape against a real
  one when `SNOWFLAKE_*` is set; replace these with recordings when there is an account to
  record from.
