"""Tests for the catalog, its sqlglot schema, and the TTL cache.

The property under test in the first half is that `Catalog` and the `MappingSchema` it
produces fold identifiers identically. RESOLVE resolves against the schema and POLICY
matches against the catalog; if the two disagreed about what "the same column" is, a
reference could resolve to a column policy failed to recognise -- masking laundering
arriving through identifier casing rather than through an expression.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
import sqlglot
from sqlglot.errors import OptimizeError
from sqlglot.optimizer.qualify import qualify

from sql_warden.catalog import (
    Catalog,
    CatalogCache,
    Column,
    DuplicateTable,
    Table,
    catalog_of,
    fold,
)

CUSTOMERS = Table(
    schema="analytics",
    name="customers",
    columns=(
        Column(name="id", data_type="BIGINT", nullable=False, is_primary_key=True),
        Column(name="email", data_type="TEXT", nullable=True),
    ),
    row_estimate=10_000,
)

ACCOUNTS = Table(
    schema="analytics",
    name="accounts",
    columns=(
        Column(name="id", data_type="BIGINT", nullable=False, is_primary_key=True),
        Column(
            name="customer_id",
            data_type="BIGINT",
            nullable=False,
            references="analytics.customers.id",
        ),
    ),
)


def catalog(dialect: str = "postgres") -> Catalog:
    return catalog_of(dialect, [CUSTOMERS, ACCOUNTS])


# -- identifier folding ---------------------------------------------------------------


@pytest.mark.parametrize("written", ["customers", "CUSTOMERS", "Customers"])
def test_postgres_folds_case_insensitively(written: str) -> None:
    """Postgres lowercases unquoted identifiers, so all three name one table."""
    assert catalog("postgres").table("analytics", written) is CUSTOMERS


@pytest.mark.parametrize("written", ["customers", "CUSTOMERS", "Customers"])
def test_snowflake_folds_the_other_way(written: str) -> None:
    """Snowflake uppercases. Same lookups resolve, by the opposite rule -- which is why
    folding is taken from the dialect rather than hand-rolled as `.lower()`.
    """
    snowflake = catalog_of("snowflake", [CUSTOMERS])
    assert snowflake.table("ANALYTICS", written) is CUSTOMERS
    assert fold("Customers", "snowflake") == "CUSTOMERS"
    assert fold("Customers", "postgres") == "customers"


def test_unknown_table_is_none_not_an_error() -> None:
    assert catalog().table("analytics", "nope") is None
    assert catalog().table("other", "customers") is None


def test_column_lookup_folds_too() -> None:
    assert CUSTOMERS.column("EMAIL", "postgres") is not None
    assert CUSTOMERS.column("nope", "postgres") is None


def test_duplicate_tables_are_refused() -> None:
    """Two tables that fold to one name would leave one of them invisible to RESOLVE while
    remaining perfectly queryable on the database.
    """
    shouty = Table(schema="analytics", name="CUSTOMERS", columns=())

    with pytest.raises(DuplicateTable, match="unreachable"):
        catalog_of("postgres", [CUSTOMERS, shouty])


def test_the_same_pair_is_not_a_duplicate_under_a_case_sensitive_reading() -> None:
    """Sanity check on the test above: the collision is caused by folding, so a dialect
    that folds the other way still collides. Nothing here is case-*sensitive*.
    """
    shouty = Table(schema="analytics", name="CUSTOMERS", columns=())

    with pytest.raises(DuplicateTable):
        catalog_of("snowflake", [CUSTOMERS, shouty])


def test_schemas_are_folded_deduplicated_and_ordered() -> None:
    mixed = catalog_of(
        "postgres",
        [CUSTOMERS, Table(schema="ANALYTICS", name="orders", columns=()), ACCOUNTS],
    )

    assert mixed.schemas == ("analytics",)


# -- the sqlglot schema ---------------------------------------------------------------


def test_schema_carries_every_table_and_column() -> None:
    schema = catalog().to_sqlglot_schema()

    assert schema.column_names("analytics.customers") == ["id", "email"]
    assert schema.column_names("analytics.accounts") == ["id", "customer_id"]


def test_schema_depth_is_schema_dot_table() -> None:
    """Two levels, not three. sqlglot infers db/catalog nesting from depth, and a
    three-level mapping would make every table reference in RESOLVE fail to match.
    """
    assert catalog().to_sqlglot_schema().depth() == 2


def test_resolve_expands_stars_to_qualified_columns() -> None:
    """The finding #3 control, asserted end to end against a real catalog.

    `SELECT *` contains no `email` node to rewrite. If star expansion did not happen before
    POLICY, masking would silently do nothing on the one query shape most likely to be
    issued. This test is why RESOLVE runs `expand_stars=True`.
    """
    resolved = qualify(
        sqlglot.parse_one("SELECT * FROM analytics.customers", dialect="postgres"),
        schema=catalog().to_sqlglot_schema(),
        dialect="postgres",
        validate_qualify_columns=True,
        expand_stars=True,
    )

    sql = resolved.sql(dialect="postgres")
    assert "*" not in sql
    assert '"customers"."email"' in sql


def test_resolve_rejects_an_unknown_column() -> None:
    """`OptimizeError` is the RESOLVE rejection, sourced from sqlglot rather than a
    hand-rolled walker. Pinned here so a sqlglot upgrade that stops raising is caught.
    """
    with pytest.raises(OptimizeError):
        qualify(
            sqlglot.parse_one("SELECT nope FROM analytics.customers", dialect="postgres"),
            schema=catalog().to_sqlglot_schema(),
            dialect="postgres",
            validate_qualify_columns=True,
        )


def test_resolve_rejects_an_unknown_table() -> None:
    with pytest.raises(OptimizeError):
        qualify(
            sqlglot.parse_one("SELECT id FROM analytics.ghost", dialect="postgres"),
            schema=catalog().to_sqlglot_schema(),
            dialect="postgres",
            validate_qualify_columns=True,
        )


@pytest.mark.parametrize("written", ["analytics.CUSTOMERS", "ANALYTICS.Customers"])
def test_a_case_variant_reference_resolves_on_postgres(written: str) -> None:
    """The catalog-side property that matters: the schema handed to `qualify()` folds the
    same way `Catalog.table()` does, so the two cannot disagree about identity.
    """
    resolved = qualify(
        sqlglot.parse_one(f"SELECT email FROM {written}", dialect="postgres"),
        schema=catalog().to_sqlglot_schema(),
        dialect="postgres",
        validate_qualify_columns=True,
    )

    assert '"email"' in resolved.sql(dialect="postgres")


def test_identifiers_needing_quotes_survive() -> None:
    """A table named after a reserved word renders quoted rather than producing a query the
    database would reject or, worse, reinterpret.
    """
    reserved = catalog_of(
        "postgres",
        [
            Table(
                schema="analytics",
                name="order",
                columns=(Column(name="user name", data_type="TEXT", nullable=True),),
            )
        ],
    )

    resolved = qualify(
        sqlglot.parse_one('SELECT * FROM analytics."order"', dialect="postgres"),
        schema=reserved.to_sqlglot_schema(),
        dialect="postgres",
        validate_qualify_columns=True,
        expand_stars=True,
    )

    sql = resolved.sql(dialect="postgres")
    assert '"order"' in sql
    assert '"user name"' in sql


def test_a_quoted_mixed_case_column_fails_closed() -> None:
    """The documented trade-off of `normalize=True`, pinned so it stays a known limitation
    rather than becoming a surprise.

    A column created as a quoted mixed-case identifier folds to lower case in the schema and
    can no longer be resolved. That is a false rejection -- `UNKNOWN_OBJECT`, nothing runs.
    The alternative, dropping normalisation, would let a reference reach a column under a
    spelling policy matching did not recognise. This assertion exists so anyone tempted to
    "fix" it has to delete a test that says why not.
    """
    quoted = catalog_of(
        "postgres",
        [Table(schema="analytics", name="t", columns=(Column("Email", "TEXT", True),))],
    )

    with pytest.raises(OptimizeError):
        qualify(
            sqlglot.parse_one('SELECT "Email" FROM analytics.t', dialect="postgres"),
            schema=quoted.to_sqlglot_schema(),
            dialect="postgres",
            validate_qualify_columns=True,
        )


# -- the TTL cache --------------------------------------------------------------------


class FakeClock:
    """A clock that only moves when a test moves it. TTL expiry is tested by arithmetic,
    not by sleeping -- a suite that sleeps to prove a timeout is a suite nobody runs.
    """

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class CountingIntrospector:
    def __init__(self, catalog: Catalog) -> None:
        self._catalog = catalog
        self.calls = 0

    async def __call__(self) -> Catalog:
        self.calls += 1
        return self._catalog


async def test_first_get_introspects() -> None:
    clock = FakeClock()
    cache = CatalogCache(timedelta(minutes=5), clock=clock)
    introspect = CountingIntrospector(catalog())

    assert await cache.get(introspect) is introspect._catalog
    assert introspect.calls == 1


async def test_a_fresh_entry_is_not_reintrospected() -> None:
    clock = FakeClock()
    cache = CatalogCache(timedelta(minutes=5), clock=clock)
    introspect = CountingIntrospector(catalog())

    await cache.get(introspect)
    clock.advance(299)
    await cache.get(introspect)

    assert introspect.calls == 1


async def test_an_expired_entry_is_refreshed() -> None:
    clock = FakeClock()
    cache = CatalogCache(timedelta(minutes=5), clock=clock)
    introspect = CountingIntrospector(catalog())

    await cache.get(introspect)
    clock.advance(300)
    await cache.get(introspect)

    assert introspect.calls == 2


async def test_expiry_boundary_is_exclusive() -> None:
    """At exactly the TTL the entry is stale. Stated in a test because "within 5 minutes"
    and "up to and including 5 minutes" are both defensible and only one is implemented.
    """
    clock = FakeClock()
    cache = CatalogCache(timedelta(seconds=10), clock=clock)
    introspect = CountingIntrospector(catalog())

    await cache.get(introspect)
    clock.advance(9.999)
    await cache.get(introspect)
    assert introspect.calls == 1

    clock.advance(0.001)
    await cache.get(introspect)
    assert introspect.calls == 2


async def test_invalidate_forces_a_refresh() -> None:
    clock = FakeClock()
    cache = CatalogCache(timedelta(minutes=5), clock=clock)
    introspect = CountingIntrospector(catalog())

    await cache.get(introspect)
    cache.invalidate()
    await cache.get(introspect)

    assert introspect.calls == 2


async def test_a_failed_refresh_propagates_rather_than_serving_stale() -> None:
    """Fail closed. If introspection fails because a table was dropped or a grant revoked,
    resolving against the catalog from before is resolving against a database that no
    longer exists.
    """
    clock = FakeClock()
    cache = CatalogCache(timedelta(seconds=10), clock=clock)
    good = CountingIntrospector(catalog())
    await cache.get(good)
    clock.advance(11)

    async def boom() -> Catalog:
        raise ConnectionError("target unreachable")

    with pytest.raises(ConnectionError):
        await cache.get(boom)


async def test_a_failed_first_load_leaves_the_cache_empty() -> None:
    cache = CatalogCache(timedelta(seconds=10), clock=FakeClock())

    async def boom() -> Catalog:
        raise ConnectionError("target unreachable")

    with pytest.raises(ConnectionError):
        await cache.get(boom)

    introspect = CountingIntrospector(catalog())
    assert await cache.get(introspect) is introspect._catalog


async def test_concurrent_misses_introspect_once() -> None:
    """A cold cache hit by a burst of queries must produce one introspection, not N.

    An agent's opening burst is exactly when this happens, and introspection is several
    catalog queries against the target -- the moment the server is least able to afford
    multiplying them.
    """
    clock = FakeClock()
    cache = CatalogCache(timedelta(minutes=5), clock=clock)
    calls = 0
    started = asyncio.Event()

    async def slow() -> Catalog:
        nonlocal calls
        calls += 1
        started.set()
        await asyncio.sleep(0)  # yield, so the other waiters get to run
        return catalog()

    await asyncio.gather(*(cache.get(slow) for _ in range(10)))

    assert calls == 1
