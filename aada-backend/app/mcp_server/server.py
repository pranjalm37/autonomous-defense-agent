"""
MCP server — exposes the AADA security tools over the Model Context Protocol.

MCP architecture (how this fits together)
-----------------------------------------
MCP is an open, JSON-RPC 2.0 protocol that standardizes how an LLM application
(the *host* — any MCP-compatible client) connects to external
capabilities. The host runs one MCP *client* per *server*. A server exposes three
things; this one focuses on TOOLS:
    - tools      model-controlled functions (what we implement here)
    - resources  app-controlled readable data (files, rows)
    - prompts    user-controlled prompt templates

Tool calling, end to end:
    1. Client connects and calls `initialize`, then `tools/list`.
    2. `tools/list` returns each tool's name, description, and JSON `inputSchema`
       (derived here from the Pydantic input model). The model reads these to
       decide *when* and *how* to call a tool.
    3. The model emits a tool call; the client sends `tools/call` with arguments.
    4. We validate the arguments, run the handler, and return content. The result
       re-enters the model's context, and it reasons about the next step.

Run it:
    python -m app.mcp_server.server          # stdio transport

Register with an MCP-compatible host via its client config file:
    {
      "mcpServers": {
        "aada-security": {
          "command": "python",
          "args": ["-m", "app.mcp_server.server"],
          "cwd": "/path/to/aada-backend"
        }
      }
    }

The tool logic lives in the registry (transport-agnostic); this module is only the
protocol adapter, so it stays thin and the SDK is imported lazily.
"""
from __future__ import annotations

import json

from app.logging_config import get_logger
from app.mcp_server.context import ToolContext, build_app_context
from app.mcp_server.tools import build_registry

logger = get_logger(__name__)
SERVER_NAME = "aada-security"


def build_mcp_server(context: ToolContext | None = None):
    """Create the MCP Server, wiring our registry into list_tools / call_tool."""
    from mcp.server import Server          # lazy import (SDK optional at import time)
    from mcp.types import TextContent, Tool

    registry = build_registry()
    ctx = context or build_app_context()
    server = Server(SERVER_NAME)

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        # tools/list — advertise name + description + JSON Schema for each tool.
        return [
            Tool(name=s.name, description=s.description, inputSchema=s.json_schema())
            for s in registry.list_specs()
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        # tools/call — validate args, execute, return JSON content.
        logger.info("mcp_tool_call", tool=name)
        result = await registry.execute(name, arguments or {}, ctx)
        return [TextContent(type="text", text=json.dumps(result.to_dict(), default=str))]

    return server


async def _run_stdio() -> None:
    from mcp.server.stdio import stdio_server

    server = build_mcp_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    import anyio
    logger.info("mcp_server_start", server=SERVER_NAME)
    anyio.run(_run_stdio)


if __name__ == "__main__":
    main()
