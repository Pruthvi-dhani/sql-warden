"""The query admission pipeline: PARSE, SHAPE, RESOLVE, POLICY, COST, EXECUTE, RECORD.

Orchestration only. Nothing here should reference a specific engine by name -- if a stage
finds itself branching on which engine is in use, that is a signal the capability belongs
on the `Engine` protocol instead, declared by the engine and read by the pipeline.
"""
