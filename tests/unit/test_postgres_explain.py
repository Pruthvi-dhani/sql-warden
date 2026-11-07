"""Turning Postgres's EXPLAIN (FORMAT JSON) output into a CostEstimate, from recorded plans."""

from typing import Any

import pytest

from sql_warden.engines import CostEstimate
from sql_warden.engines.postgres import cost_estimate, describe_node


def node(
    kind: str, total: float, rows: int, *plans: dict[str, Any], **fields: Any
) -> dict[str, Any]:
    """A plan node with the fields cost_estimate reads; the rest of a real node is left out."""
    return {
        "Node Type": kind,
        "Total Cost": total,
        "Plan Rows": rows,
        **fields,
        **({"Plans": list(plans)} if plans else {}),
    }


def seq_scan(relation: str, total: float, rows: int, **fields: Any) -> dict[str, Any]:
    return node("Seq Scan", total, rows, **{"Relation Name": relation, "Alias": relation, **fields})


# Plans as Postgres 16 gives them for the demo warehouse (1M orders), trimmed.
INDEXED_LOOKUP = {  # SELECT * FROM orders WHERE id = 42 LIMIT 101
    "Plan": node(
        "Limit",
        8.44,
        1,
        node(
            "Index Scan",
            8.44,
            1,
            **{"Index Name": "orders_pkey", "Relation Name": "orders", "Alias": "orders"},
        ),
    )
}
COUNT_OF_A_CROSS_JOIN = {  # SELECT COUNT(*) FROM orders AS a CROSS JOIN orders AS b LIMIT 101
    "Plan": node(
        "Limit",
        12847522945.56,
        1,
        node(
            "Aggregate",
            12847522945.56,
            1,
            node(
                "Gather",
                12847522945.54,
                2,
                node(
                    "Aggregate",
                    12847521945.34,
                    1,
                    node(
                        "Nested Loop",
                        11805855278.67,
                        416666666667,
                        seq_scan("orders", 12500.67, 416667, Alias="a", **{"Parallel Aware": True}),
                        seq_scan("orders", 18334.0, 1000000, Alias="b"),
                        **{"Join Type": "Inner"},
                    ),
                    Strategy="Plain",
                    **{"Partial Mode": "Partial"},
                ),
            ),
            Strategy="Plain",
            **{"Partial Mode": "Finalize"},
        ),
    ),
    "JIT": {"Functions": 4},
}
A_CROSS_JOIN_THAT_STOPS_AT_THE_LIMIT = {  # SELECT * FROM orders a CROSS JOIN orders b LIMIT 101
    "Plan": node(
        "Limit",
        2.05,
        101,
        node(
            "Nested Loop",
            20313039168.0,
            1000000000000,
            seq_scan("orders", 18334.0, 1000000, Alias="a"),
            node("Materialize", 31147.0, 1000000, seq_scan("orders", 18334.0, 1000000, Alias="b")),
        ),
    )
}
A_SCAN_UNDER_THE_LIMIT = {  # SELECT id FROM orders LIMIT 101
    "Plan": node("Limit", 1.85, 101, seq_scan("orders", 18334.0, 1000000))
}


def test_an_indexed_lookup() -> None:
    assert cost_estimate(INDEXED_LOOKUP) == CostEstimate(
        total_cost=8.44, est_rows=1, top_node="Index Scan using orders_pkey on orders"
    )


def test_the_count_of_a_cross_join() -> None:
    estimate = cost_estimate(COUNT_OF_A_CROSS_JOIN)
    assert (estimate.total_cost, estimate.est_rows) == (12847522945.56, 1)
    assert estimate.top_node == "Nested Loop"  # what makes it expensive, not the Limit on top


def test_the_root_is_the_estimate_even_when_a_step_below_costs_more() -> None:
    # A Limit stops its input early, and the planner prices that in: the whole query is what
    # it would cost, the expensive step underneath is what it would cost without the Limit.
    estimate = cost_estimate(A_CROSS_JOIN_THAT_STOPS_AT_THE_LIMIT)
    assert (estimate.total_cost, estimate.est_rows, estimate.top_node) == (2.05, 101, "Nested Loop")
    assert cost_estimate(A_SCAN_UNDER_THE_LIMIT).top_node == "Seq Scan on orders"


def test_the_plan_is_kept_but_left_out_of_equality_and_repr() -> None:
    estimate = cost_estimate(COUNT_OF_A_CROSS_JOIN)
    assert estimate.raw is COUNT_OF_A_CROSS_JOIN
    assert "JIT" not in repr(estimate)
    assert estimate == CostEstimate(estimate.total_cost, estimate.est_rows, estimate.top_node)


def test_of_equally_costly_steps_the_outermost_is_named() -> None:
    plan = {"Plan": node("Append", 20.0, 2, seq_scan("a", 10.0, 1), seq_scan("b", 10.0, 1))}
    assert cost_estimate(plan).top_node == "Seq Scan on a"


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"Node Type": "Result"}, "Result"),
        (
            {"Node Type": "Seq Scan", "Relation Name": "orders", "Alias": "o"},
            "Seq Scan on orders o",
        ),
        (
            {
                "Node Type": "Seq Scan",
                "Relation Name": "orders",
                "Alias": "orders",
                "Parallel Aware": True,
            },
            "Parallel Seq Scan on orders",
        ),
        (
            {
                "Node Type": "Index Only Scan",
                "Index Name": "orders_customer_id_idx",
                "Relation Name": "orders",
                "Alias": "orders",
            },
            "Index Only Scan using orders_customer_id_idx on orders",
        ),
        (
            {"Node Type": "Bitmap Index Scan", "Index Name": "orders_customer_id_idx"},
            "Bitmap Index Scan on orders_customer_id_idx",
        ),
        ({"Node Type": "Aggregate", "Strategy": "Plain"}, "Aggregate"),
        ({"Node Type": "Aggregate", "Strategy": "Hashed"}, "HashAggregate"),
        (
            {"Node Type": "Aggregate", "Strategy": "Sorted", "Partial Mode": "Finalize"},
            "Finalize GroupAggregate",
        ),
        ({"Node Type": "Aggregate", "Strategy": "Plain", "Partial Mode": "Simple"}, "Aggregate"),
        ({"Node Type": "Hash Join", "Join Type": "Inner"}, "Hash Join"),
        ({"Node Type": "Hash Join", "Join Type": "Left"}, "Hash Left Join"),
        ({"Node Type": "Merge Join", "Join Type": "Full"}, "Merge Full Join"),
        ({"Node Type": "Nested Loop", "Join Type": "Anti"}, "Nested Loop Anti Join"),
        ({"Node Type": "CTE Scan", "CTE Name": "recent", "Alias": "r"}, "CTE Scan on recent r"),
        (
            {"Node Type": "Function Scan", "Function Name": "generate_series", "Alias": "g"},
            "Function Scan on generate_series g",
        ),
        ({"Node Type": "Subquery Scan", "Alias": "s"}, "Subquery Scan on s"),
        ({"Node Type": "Values Scan", "Alias": "*VALUES*"}, "Values Scan on *VALUES*"),
    ],
)
def test_nodes_are_named_as_explain_names_them(fields: dict[str, Any], expected: str) -> None:
    assert describe_node(fields) == expected
