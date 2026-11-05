"""Pointing at the error in the SQL that was sent, not in psycopg's DECLARE ... CURSOR FOR."""

from sql_warden.engines.postgres import point_at


def test_the_caret_sits_under_the_offset() -> None:
    assert point_at("SELECT nope FROM products", 7) == [
        "  SELECT nope FROM products",
        "         ^",
    ]


def test_the_end_of_the_sql_can_be_pointed_at() -> None:
    # "syntax error at end of input" points one past the last character.
    assert point_at("SELECT 1 +", 10) == ["  SELECT 1 +", "            ^"]


def test_only_the_line_with_the_error_is_shown() -> None:
    sql = "SELECT id\nFROM products\nWHERE nope = 1"
    assert point_at(sql, sql.index("nope")) == ["  WHERE nope = 1", "        ^"]


def test_long_lines_are_cut_around_the_error() -> None:
    sql = "SELECT " + ", ".join(f"c{i}" for i in range(40)) + ", nope FROM t"
    text, caret = point_at(sql, sql.index("nope"))
    assert text.startswith("  ...")
    assert not text.endswith("...")  # the line ends within the window
    assert text[caret.index("^") :].startswith("nope")
    assert len(text) <= 2 + 3 + 80 + 3


def test_both_sides_are_cut_on_a_very_long_line() -> None:
    sql = "x" * 100 + "!" + "y" * 100
    text, caret = point_at(sql, 100)
    assert text == "  ..." + "x" * 40 + "!" + "y" * 39 + "..."
    assert text[caret.index("^")] == "!"
