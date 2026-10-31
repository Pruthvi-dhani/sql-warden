import pytest
from sqlglot import exp

from sql_warden.models import RefusalCode
from sql_warden.pipeline import CheckContext, ParseCheck


def _run(sql: str) -> tuple[CheckContext, str | None]:
    ctx = CheckContext(sql=sql, dialect="postgres")
    refusal = ParseCheck().run(ctx)
    if refusal is None:
        return ctx, None
    assert refusal.code is RefusalCode.PARSE_ERROR
    return ctx, refusal.reason


def test_valid_sql_is_parsed_once_into_the_context() -> None:
    ctx, reason = _run("select id from products where id = 1")
    assert reason is None
    assert len(ctx.statements) == 1
    assert isinstance(ctx.statements[0], exp.Select)


def test_every_statement_is_kept_for_later_checks() -> None:
    # Refusing multiple statements is the shape check's job; parse just records them.
    ctx, reason = _run("select 1; select 2")
    assert reason is None
    assert len(ctx.statements) == 2


@pytest.mark.parametrize("sql", ["", "   ", ";", " ; ; "])
def test_empty_queries_are_refused(sql: str) -> None:
    assert _run(sql)[1] == "the query is empty"


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        ("SELEC 1", "Invalid expression / Unexpected token (line 1, col 7)"),
        ("select (1", "Expecting ) (line 1, col 9)"),
        ("select 1 from", "Expected table name but got end of query (line 1, col 13)"),
        ("select * from t where", "incomplete WHERE clause (line 1, col 21)"),
        ("select a from t order by", "incomplete ORDER BY clause (line 1, col 24)"),
    ],
)
def test_malformed_sql_gets_a_readable_reason(sql: str, reason: str) -> None:
    assert _run(sql)[1] == reason


@pytest.mark.parametrize(
    "sql", ["select * from t where", "select 1 from", "select a from t join", "select 1 +"]
)
def test_reasons_never_leak_python_reprs(sql: str) -> None:
    reason = _run(sql)[1]
    assert reason is not None
    assert "<Token" not in reason
    assert "<class" not in reason
    assert "\x1b[" not in reason  # no terminal colour codes


def test_dialect_is_respected() -> None:
    # Snowflake's QUALIFY parses there; the check must use the configured dialect.
    ctx = CheckContext(
        sql="select id from t qualify row_number() over (order by id) = 1", dialect="snowflake"
    )
    assert ParseCheck().run(ctx) is None
