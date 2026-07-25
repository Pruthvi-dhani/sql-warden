"""Stage 0 smoke test: the package imports and the test harness runs."""

from __future__ import annotations

import sql_warden


def test_package_imports_and_declares_a_version() -> None:
    assert sql_warden.__version__


async def test_asyncio_mode_is_wired() -> None:
    """pytest-asyncio runs bare `async def` tests without a decorator (asyncio_mode=auto).

    Asserted here because every stage from 4 onward depends on it, and a silently
    skipped async test is worse than a failing one.
    """
    assert True
