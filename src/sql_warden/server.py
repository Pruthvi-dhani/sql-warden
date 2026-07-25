"""MCP server entry point.

This module is the *only* place in the package permitted to import from `mcp`. The
2026-07-28 spec moves MCP from a stateful bidirectional protocol to stateless
request/response and rewrites the low-level `Server` interface, so confining the
dependency here keeps that migration to a single file. See implementation-plan.md
finding #1.

The tool surface lands in Stage 12.
"""

from __future__ import annotations


def main() -> None:
    """Run the sql-warden MCP server over stdio."""
    raise NotImplementedError("The MCP tool surface is implemented in Stage 12.")
