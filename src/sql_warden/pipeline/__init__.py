"""The query admission pipeline: PARSE, SHAPE, RESOLVE, POLICY, COST, EXECUTE, RECORD.

Orchestration only. Nothing in this package may reference a specific engine by name --
if a stage needs to branch on the engine, that capability belongs on the `Engine`
protocol instead. Enforced by `tests/unit/test_engine_isolation.py`.
"""
