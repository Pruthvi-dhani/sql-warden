"""Stage 0 smoke test: Testcontainers can start Postgres 16 and we can talk to it.

Every integration test from Stage 4 onward stands on this. Proving the container
runtime works here means a later failure is about our code, not our harness.
"""

from __future__ import annotations

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer


@pytest.mark.integration
def test_testcontainers_postgres_is_reachable() -> None:
    with PostgresContainer("postgres:16") as pg:
        dsn = pg.get_connection_url(driver=None)
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            row = cur.fetchone()
            assert row is not None
            assert row[0] == 1

            cur.execute("SHOW server_version_num")
            version = cur.fetchone()
            assert version is not None
            # Postgres 16 or newer; plan.md pins 16 and pg_class/reltuples
            # introspection in Stage 4 assumes a modern catalog layout.
            assert int(version[0]) >= 160000
