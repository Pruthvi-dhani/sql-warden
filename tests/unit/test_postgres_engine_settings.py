import pytest

from sql_warden.engines.postgres import PostgresEngine


def test_defaults() -> None:
    engine = PostgresEngine("postgresql://localhost/db")
    assert engine.statement_timeout_ms == 5_000
    assert engine.max_rows == 1_000


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"statement_timeout_ms": 0}, "statement_timeout_ms"),
        ({"max_rows": 0}, "max_rows"),
        ({"max_rows": -5}, "max_rows"),
        ({"connect_timeout_s": 0}, "connect_timeout_s"),
    ],
)
def test_rejects_non_positive_limits(kwargs: dict[str, int], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        PostgresEngine("postgresql://localhost/db", **kwargs)
