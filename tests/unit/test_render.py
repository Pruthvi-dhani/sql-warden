from datetime import date
from decimal import Decimal

from sql_warden.engines import Result
from sql_warden.render import format_table, format_value


def _result(
    columns: tuple[str, ...],
    rows: tuple[tuple[object, ...], ...],
    *,
    truncated: bool = False,
) -> Result:
    return Result(columns=columns, rows=rows, truncated=truncated, duration_ms=12.3)


def test_format_value_renders_null_and_python_types() -> None:
    assert format_value(None) == "NULL"
    assert format_value(Decimal("1.50")) == "1.50"
    assert format_value(date(2024, 1, 2)) == "2024-01-02"


def test_columns_are_aligned_to_the_widest_cell() -> None:
    table = format_table(_result(("id", "name"), ((1, "Ada"), (22, None))))
    assert table.splitlines() == [
        "id | name",
        "---+-----",
        "1  | Ada",
        "22 | NULL",
        "(2 rows, 12 ms)",
    ]


def test_empty_result_still_shows_headers() -> None:
    assert format_table(_result(("id",), ())).splitlines() == ["id", "--", "(0 rows, 12 ms)"]


def test_footer_singular_row() -> None:
    assert format_table(_result(("n",), ((1,),))).splitlines()[-1] == "(1 row, 12 ms)"


def test_footer_flags_truncation() -> None:
    table = format_table(_result(("n",), ((1,), (2,)), truncated=True))
    assert table.splitlines()[-1] == "(2 rows, truncated at the row cap, 12 ms)"
