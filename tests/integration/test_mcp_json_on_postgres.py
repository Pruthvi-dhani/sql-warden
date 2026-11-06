"""The .mcp.json.example entry, launched the way Claude Code launches it, against the demo seed.

Claude Code expands ${VAR} and ${VAR:-default} in an entry's command and args from its own
environment, then starts the server over stdio with CLAUDE_PROJECT_DIR set to the project root.
This test does the same, so the example in the repo is one that is known to work.
"""

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from mcp import Client, StdioServerParameters

from tests.integration.conftest import Warehouse

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

REPO = Path(__file__).parents[2]
EXAMPLE = REPO / ".mcp.json.example"
_VARIABLE = re.compile(r"\$\{(?P<name>\w+)(?::-(?P<default>[^}]*))?\}")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def expand(value: str, env: Mapping[str, str]) -> str:
    """Claude Code's .mcp.json expansion; an unset variable with no default stays as written."""

    def replace(match: re.Match[str]) -> str:
        if match["name"] in env:
            return env[match["name"]]
        return match["default"] if match["default"] is not None else match[0]

    return _VARIABLE.sub(replace, value)


@pytest.fixture
def params(warehouse: Warehouse, audit_dsn: str, tmp_path: Path) -> StdioServerParameters:
    entry = json.loads(EXAMPLE.read_text())["mcpServers"]["sql-warden"]
    config = tmp_path / "warden.yaml"
    config.write_text("version: 1\nwarehouse:\n  max_rows: 3\n")
    return StdioServerParameters(
        # CLAUDE_PROJECT_DIR is not in Claude Code's own environment, so it expands to the default.
        command=expand(entry["command"], {}),
        args=[expand(arg, {}) for arg in entry["args"]],
        env={
            "CLAUDE_PROJECT_DIR": str(REPO),
            "SQL_WARDEN_DSN": warehouse.reader_dsn,
            "SQL_WARDEN_AUDIT_DSN": audit_dsn,
            "SQL_WARDEN_CONFIG": str(config),
        },
        cwd=REPO,
    )


async def test_the_example_entry_serves_the_warehouse(params: StdioServerParameters) -> None:
    async with Client(params) as client:
        instructions = client.instructions
        names = {tool.name for tool in (await client.list_tools()).tools}
        tables = _structured(await client.call_tool("list_tables", {}))
        ran = await client.call_tool("run_query", {"sql": "select id from products order by id"})

    assert instructions is not None
    assert "read-only SQL" in instructions
    assert names == {"run_query", "check_query", "list_tables", "describe_table"}
    assert {t["name"] for t in tables["tables"]} == {
        "customers",
        "employee_salaries",
        "orders",
        "products",
    }
    assert ran.is_error is False
    payload = _structured(ran)
    assert payload["sql"] == "SELECT id FROM products ORDER BY id LIMIT 4"  # max_rows from config
    assert payload["result"]["rows"] == [[1], [2], [3]]
    assert payload["result"]["truncated"] is True


@pytest.mark.parametrize(
    ("sql", "code"),
    [
        ("delete from orders", "NOT_A_SELECT"),
        ("select pg_sleep(60)", "FUNCTION_NOT_ALLOWED"),
        ("with x as (delete from orders returning *) select count(*) from x", "NOT_READ_ONLY"),
    ],
)
async def test_refusals_reach_the_agent(params: StdioServerParameters, sql: str, code: str) -> None:
    async with Client(params) as client:
        result = await client.call_tool("run_query", {"sql": sql})
    assert result.is_error is True
    payload = _structured(result)
    assert (payload["check"], payload["code"]) == ("shape", code)
    assert payload["reason"]


def _structured(result: Any) -> dict[str, Any]:
    assert result.structured_content is not None
    content: dict[str, Any] = result.structured_content
    return content
