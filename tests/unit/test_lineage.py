"""Following masked columns through a query: into its outputs, and into uses that leak."""

import pytest
import sqlglot
from sqlglot.optimizer.normalize_identifiers import normalize_identifiers

from sql_warden.catalog import Catalog
from sql_warden.engines import Column, Table
from sql_warden.pipeline.lineage import NOTHING, Flow, Lineage, LineageError, MaskedColumn, trace
from tests.unit import dialects
from tests.unit.conftest import FakeEngine

pytestmark = pytest.mark.usefixtures("dialect")  # every test here runs under each dialect
PG = pytest.mark.postgres_only


def _table(name: str, *columns: str) -> Table:
    return Table("public", name, tuple(Column(column, "text") for column in columns))


CATALOG = (
    _table("customers", "id", "full_name", "email", "phone", "ssn"),
    _table("orders", "id", "customer_id", "quantity", "note"),
    _table("products", "id", "name"),
)
EMAIL = ("public", "customers", "email")
SSN = ("public", "customers", "ssn")
MASKED = {EMAIL, SSN}


def _masked() -> set[MaskedColumn]:
    """MASKED, as the running dialect stores the names."""
    return {dialects.names(column) for column in MASKED}


def _follow(tree: sqlglot.Expr, masked: set[MaskedColumn] | None = None) -> Lineage:
    dialect = dialects.current()
    catalog = Catalog(FakeEngine(catalog=dialects.catalog(CATALOG)), dialect=dialect)
    return trace(
        tree,
        _masked() if masked is None else masked,
        schema=catalog.schema(),
        dialect=dialect,
        default_schema=dialects.stored("public"),
    )


def _parsed(sql: str) -> sqlglot.Expr:
    return sqlglot.parse_one(sql, dialect=dialects.current())


def _trace(sql: str) -> Lineage:
    # As the masking check gets it: parsed, with unquoted names folded.
    return _follow(normalize_identifiers(_parsed(sql), dialect=dialects.current()))


def _outputs(sql: str) -> str:
    """The result's columns as text: `id email=email total~email+ssn`. `=` is a masked column
    unchanged, `~` something made from masked columns."""
    described = []
    for output in _trace(sql).outputs:
        columns = "+".join(sorted(column[2] for column in output.flow.columns))
        sign = "" if not columns else "=" if output.flow.unchanged else "~"
        described.append(f"{output.name}{sign}{columns}")
    return dialects.text(" ".join(described))


def _uses(sql: str) -> list[str]:
    return [dialects.text(f"{use.column[2]} in {use.where}") for use in _trace(sql).uses]


class TestAMaskedColumnSelectedAsItIs:
    """Reaches the output unchanged, so its own mask applies, and is not a use."""

    @pytest.mark.parametrize(
        ("sql", "outputs"),
        [
            ("select id, email, ssn from customers", "id email=email ssn=ssn"),
            ("select email as e from customers", "e=email"),
            ("select (email) from customers", "email=email"),
            ("select c.email from customers c where c.id = 5", "email=email"),
            ("select * from customers", "id full_name email=email phone ssn=ssn"),
            (
                "select c.*, o.quantity from customers c join orders o on o.customer_id = c.id",
                "id full_name email=email phone ssn=ssn quantity",
            ),
            ("with x as (select email e, id from customers) select e from x", "e=email"),
            (
                "with a as (select ssn from customers), b as (select ssn s from a) select s from b",
                "s=ssn",
            ),
            ("select t.s from (select ssn as s from customers) t", "s=ssn"),
            ("select e from (select email from customers) t(e)", "e=email"),
            ("select * from (select * from customers) t", "id full_name email=email phone ssn=ssn"),
            ("select u.e from customers c, lateral (select c.email as e) u", "e=email"),
            (
                "select email from customers union all select email from customers where id > 5",
                "email=email",
            ),
            (
                "with recursive r as (select id, ssn from customers where id = 1 union all "
                "select c.id, c.ssn from customers c join r on c.id = r.id + 1) select * from r",
                "id ssn=ssn",
            ),
            (
                "select id, email from customers where id in (select customer_id from orders) "
                "order by full_name limit 5",
                "id email=email",
            ),
        ],
    )
    def test_through_aliases_ctes_subqueries_and_union_all(self, sql: str, outputs: str) -> None:
        assert _outputs(sql) == outputs
        assert _uses(sql) == []


class TestCounting:
    def test_how_many_values_is_not_what_they_are(self) -> None:
        sql = "select count(ssn), count(distinct ssn), count(*) from customers"
        assert _outputs(sql) == "_col_0 _col_1 _col_2"
        assert _uses(sql) == []

    def test_in_a_condition_too(self) -> None:
        assert _uses("select id from customers group by id having count(ssn) > 1") == []

    def test_but_a_filtered_count_is_a_condition_on_the_values(self) -> None:
        sql = "select count(*) filter (where ssn like '1%') from customers"
        assert _outputs(sql) == "_col_0~ssn"
        (use,) = _uses(sql)  # Snowflake has no FILTER: it is read as COUNT_IF, a use all the same
        assert "customers.ssn LIKE '1%'" in use
        if dialects.current() == "postgres":
            assert use == "ssn in COUNT(*) FILTER(WHERE customers.ssn LIKE '1%')"

    def test_nor_is_any_other_aggregate(self) -> None:
        assert _uses("select max(ssn) from customers") == ["ssn in MAX(customers.ssn)"]


class TestExists:
    def test_what_an_exists_subquery_selects_doesnt_matter(self) -> None:
        sql = (
            "select id from customers c "
            "where exists (select * from customers c2 where c2.id = c.id)"
        )
        assert _uses(sql) == []

    def test_what_it_filters_on_does(self) -> None:
        sql = (
            "select o.id from orders o "
            "where exists (select 1 from customers c where c.ssn = o.note)"
        )
        assert _uses(sql) == ["ssn in WHERE"]


class TestUsesOutsideTheSelectList:
    """Which rows come back, how many, in what order: each depends on the hidden values."""

    @pytest.mark.parametrize(
        ("sql", "use"),
        [
            ("select id from customers where ssn like '123%'", "ssn in WHERE"),
            ("select o.id from orders o join customers c on c.email = o.note", "email in JOIN"),
            ("select c.id from customers c join customers c2 using (email)", "email in JOIN"),
            ("select ssn, count(*) from customers group by ssn", "ssn in GROUP BY"),
            ("select ssn, count(*) from customers group by 1", "ssn in GROUP BY"),
            ("select id from customers group by id having max(ssn) > 'a'", "ssn in HAVING"),
            ("select id from customers order by ssn", "ssn in ORDER BY"),
            ("select ssn as s from customers order by s", "ssn in ORDER BY"),
            ("select id, ssn from customers order by 2", "ssn in ORDER BY"),
            ("select distinct ssn from customers", "ssn in DISTINCT"),
            ("select distinct on (ssn) id from customers", "ssn in DISTINCT ON"),
            pytest.param(  # Snowflake has no WINDOW clause
                "select count(*) over w from customers window w as (partition by ssn)",
                "ssn in WINDOW",
                marks=PG,
            ),
            ("select id from orders where note in (select ssn from customers)", "ssn in WHERE"),
            (
                "select c.id from customers c, unnest(string_to_array(c.ssn, '-')) as part",
                "ssn in FROM",
            ),
        ],
    )
    def test_each_clause(self, sql: str, use: str) -> None:
        assert _uses(sql) == [use]

    @pytest.mark.parametrize(
        ("sql", "use"),
        [
            (
                "select id from (select id, ssn as s from customers) t where s like '1%'",
                "ssn in WHERE",
            ),
            (
                "with x as (select ssn s from customers) select count(*) from x where s > 'a'",
                "ssn in WHERE",
            ),
            (
                "select id from (select id, ssn from customers) t order by t.ssn",
                "ssn in ORDER BY",
            ),
            (
                "select email from customers union all select email from customers order by email",
                "email in ORDER BY",
            ),
        ],
    )
    def test_under_another_name_it_is_still_the_column(self, sql: str, use: str) -> None:
        assert _uses(sql) == [use]

    @pytest.mark.parametrize(
        ("operation", "name"),
        [("union", "UNION"), ("intersect", "INTERSECT"), ("except", "EXCEPT")],
    )
    def test_set_operations_that_compare_rows(self, operation: str, name: str) -> None:
        # One row back or two says whether the guess was right.
        sql = f"select ssn from customers where id = 5 {operation} select '123-45-6789'"
        assert _uses(sql) == [f"ssn in {name}"]


class TestUsesInsideAnExpression:
    """Computed from a masked column: no mask on the result is safe, and it is a use."""

    @pytest.mark.parametrize(
        ("sql", "outputs", "use"),
        [
            ("select upper(email) from customers", "_col_0~email", "UPPER(customers.email)"),
            (
                "select full_name || ' ' || email as who from customers",
                "who~email",
                "customers.full_name || ' ' || customers.email",
            ),
            (
                "select email::varchar(3) from customers",
                "email~email",
                "CAST(customers.email AS VARCHAR(3))",
            ),
            (
                "select coalesce(ssn, 'none') from customers",
                "_col_0~ssn",
                "COALESCE(customers.ssn, 'none')",
            ),
            (
                "select ssn like '123%' as hit from customers",
                "hit~ssn",
                "customers.ssn LIKE '123%'",
            ),
            (
                "select id, row_number() over (order by ssn) as r from customers",
                "id r~ssn",
                "ROW_NUMBER() OVER (ORDER BY customers.ssn)",
            ),
        ],
    )
    def test_functions_operators_casts_and_windows(self, sql: str, outputs: str, use: str) -> None:
        assert _outputs(sql) == outputs
        assert [dialects.text(u.where) for u in _trace(sql).uses] == [use]
        assert {u.kind for u in _trace(sql).uses} == {"expression"}

    def test_an_error_can_carry_one_bit_even_when_the_result_is_hidden(self) -> None:
        sql = "select case when ssn like '123%' then 1 / (id - id) else 1 end from customers"
        (use,) = _trace(sql).uses
        assert (use.column, use.kind) == (dialects.names(SSN), "expression")
        assert use.where.lower().startswith("case when customers.ssn like '123%'")
        assert use.where.endswith("…")  # cut to a readable length
        assert len(use.where) == 60

    @pytest.mark.parametrize(
        "sql",
        [
            "select c from customers c",
            "select to_jsonb(c.*) from customers c",
            "select row_to_json(c) from customers c",
            "select (c).ssn from customers c",
        ],
    )
    def test_the_whole_row_holds_every_masked_column(self, sql: str) -> None:
        lineage = _trace(sql)
        assert lineage.outputs[0].flow == Flow(frozenset(_masked()), unchanged=False)
        assert {use.column for use in lineage.uses} == _masked()

    def test_a_subquery_used_as_a_value(self) -> None:
        sql = (
            "select o.id, (select c.ssn from customers c where c.id = o.customer_id) from orders o"
        )
        assert _outputs(sql) == "id _col_1~ssn"
        assert [use.kind for use in _trace(sql).uses] == ["expression"]

    def test_several_columns_several_uses(self) -> None:
        assert _uses("select email || ssn from customers") == [
            "email in customers.email || customers.ssn",
            "ssn in customers.email || customers.ssn",
        ]


class TestMixing:
    """UNION ALL keeps every row, so it compares nothing; but rows of two kinds can't share
    one column's mask."""

    @pytest.mark.parametrize(
        ("sql", "outputs"),
        [
            ("select email from customers union all select ssn from customers", "email~email+ssn"),
            (
                # With the column's own mask, an hmac of the guess would sit next to the hmac
                # of the value: equal tokens, right guess.
                "select ssn from customers where id = 5 union all select '123-45-6789'",
                "ssn~ssn",
            ),
            (
                "select full_name from customers union all select email from customers",
                "full_name~email",
            ),
        ],
    )
    def test_is_made_from_the_columns_not_any_one_of_them(self, sql: str, outputs: str) -> None:
        assert _outputs(sql) == outputs
        assert _uses(sql) == []  # nothing was compared or computed


class TestNothingToFollow:
    def test_a_query_that_reads_no_masked_table(self) -> None:
        assert _trace("select name from products") is NOTHING
        assert not NOTHING.masked

    def test_no_masked_columns_at_all(self) -> None:
        assert _follow(_parsed("select ssn from customers"), set()) is NOTHING

    def test_a_masked_table_read_without_its_masked_columns(self) -> None:
        lineage = _trace("select id, full_name from customers where id > 5 order by full_name")
        assert [dialects.text(output.name) for output in lineage.outputs] == ["id", "full_name"]
        assert not lineage.masked
        assert lineage.uses == ()

    def test_the_query_is_left_as_it_was(self) -> None:
        tree = _parsed("select * from customers")
        before = tree.sql(dialect=dialects.current())
        _follow(tree)
        assert tree.sql(dialect=dialects.current()) == before


class TestWhatCantBeFollowed:
    def test_a_star_over_a_source_whose_columns_are_unknown(self) -> None:
        sql = "select * from customers c, unnest(array[1, 2])"
        with pytest.raises(LineageError, match="could not tell which columns"):
            _trace(sql)

    def test_one_flow_is_one_column(self) -> None:
        with pytest.raises(ValueError, match="only one column unchanged"):
            Flow(frozenset(MASKED), unchanged=True)
