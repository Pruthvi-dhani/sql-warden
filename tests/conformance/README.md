# Engine conformance suite

**One** abstract suite, parametrised over every `Engine` implementation: introspection
shape, read-only enforcement, cost estimation, masking, row limits, timeout behaviour, and
audit record shape.

Extracted from the Postgres integration tests in Stage 13, before a second engine exists,
so that Stage 14's exit criterion can be **"this suite passes against both engines,
unmodified."** If adding Snowflake requires editing the suite, the abstraction failed and
the fix belongs in the `Engine` protocol, not in the test.

Running the identical suite green against two dissimilar engines is the evidence for the
pluggability claim — better evidence than a paragraph asserting it. See plan.md §8.
