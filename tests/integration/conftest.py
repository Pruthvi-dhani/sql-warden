from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from testcontainers.community.postgres import PostgresContainer

POSTGRES_IMAGE = "postgres:16-alpine"
WAREHOUSE_SEED = Path(__file__).parents[2] / "dev" / "warehouse_seed.sql"


@dataclass(frozen=True)
class Warehouse:
    """Connection strings for a seeded demo warehouse."""

    admin_dsn: str
    reader_dsn: str
    public_dsn: str
    """The `public` profile's role: products (id, name, price_cents) only."""


@pytest.fixture(scope="session")
def warehouse() -> Iterator[Warehouse]:
    """A throwaway Postgres seeded exactly like the docker-compose `warehouse` service."""
    container = PostgresContainer(
        POSTGRES_IMAGE,
        username="warehouse_admin",
        password="warehouse_admin",
        dbname="warehouse",
        driver=None,
    ).with_volume_mapping(
        str(WAREHOUSE_SEED), "/docker-entrypoint-initdb.d/01_warehouse_seed.sql", "ro"
    )
    with container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(5432)
        yield Warehouse(
            admin_dsn=container.get_connection_url(),
            reader_dsn=f"postgresql://warden_reader:warden_reader@{host}:{port}/warehouse",
            public_dsn=f"postgresql://warden_public:warden_public@{host}:{port}/warehouse",
        )


@pytest.fixture(scope="session")
def audit_dsn() -> Iterator[str]:
    """A throwaway Postgres for the audit log, separate from the warehouse as in production."""
    container = PostgresContainer(
        POSTGRES_IMAGE,
        username="warden_audit",
        password="warden_audit",
        dbname="audit",
        driver=None,
    )
    with container:
        yield container.get_connection_url()


@pytest.fixture(autouse=True)
def audit_env(audit_dsn: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """Point the CLI at the test audit database, so no integration test ever records into the
    demo stack's audit log, or depends on it running."""
    monkeypatch.setenv("SQL_WARDEN_AUDIT_DSN", audit_dsn)
    return audit_dsn
