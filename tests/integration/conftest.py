from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from psycopg.conninfo import make_conninfo
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
    internal_host: str
    """Where another container reaches it: its address on Docker's bridge network, port 5432."""

    def inside(self, dsn: str) -> str:
        """dsn, as another container must write it."""
        return make_conninfo(dsn, host=self.internal_host, port=5432)


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
            internal_host=_bridge_ip(container),
        )


def _bridge_ip(container: PostgresContainer) -> str:
    return container.get_docker_client().bridge_ip(container.get_wrapped_container().id)


@pytest.fixture(scope="session")
def audit_container() -> Iterator[PostgresContainer]:
    """A throwaway Postgres for the audit log, separate from the warehouse as in production."""
    container = PostgresContainer(
        POSTGRES_IMAGE,
        username="warden_audit",
        password="warden_audit",
        dbname="audit",
        driver=None,
    )
    with container:
        yield container


@pytest.fixture(scope="session")
def audit_dsn(audit_container: PostgresContainer) -> str:
    return str(audit_container.get_connection_url())


@pytest.fixture(scope="session")
def audit_internal_dsn(audit_container: PostgresContainer, audit_dsn: str) -> str:
    """The audit database, as another container reaches it."""
    return make_conninfo(audit_dsn, host=_bridge_ip(audit_container), port=5432)


@pytest.fixture(autouse=True)
def audit_env(audit_dsn: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """Point the CLI at the test audit database, so no integration test ever records into the
    demo stack's audit log, or depends on it running."""
    monkeypatch.setenv("SQL_WARDEN_AUDIT_DSN", audit_dsn)
    return audit_dsn
