"""
Tool registry — the transport-agnostic core of the MCP server.

A `ToolSpec` is everything the protocol needs to advertise and run a tool:
  - name           the identifier the model calls
  - description     what it does + WHEN to use it (this is what the model reads to
                    decide; a vague description = a tool the model misuses or skips)
  - input_model     a Pydantic model → JSON Schema for the `inputSchema` the model
                    fills, and the validator that rejects bad arguments
  - handler         the async function that does the work
  - destructive / requires_approval — safety metadata surfaced to the agent

Keeping this separate from the MCP SDK means the same registry powers the MCP
server (server.py), direct calls from the AI analyst, and the unit tests — none of
which need a live protocol connection.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from app.mcp_server.context import ToolContext, ToolResult

Handler = Callable[[BaseModel, ToolContext], Awaitable[ToolResult]]


@dataclass
class ToolSpec:
    name: str
    description: str
    input_model: type[BaseModel]
    handler: Handler
    destructive: bool = False
    requires_approval: bool = False

    def json_schema(self) -> dict:
        return self.input_model.model_json_schema()


class ToolRegistry:
    def __init__(self):
        self._specs: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._specs:
            raise ValueError(f"duplicate tool: {spec.name}")
        self._specs[spec.name] = spec

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def list_specs(self) -> list[ToolSpec]:
        return list(self._specs.values())

    async def execute(self, name: str, arguments: dict, ctx: ToolContext) -> ToolResult:
        spec = self._specs.get(name)
        if spec is None:
            return ToolResult.fail(f"unknown tool '{name}'")
        try:
            params = spec.input_model.model_validate(arguments or {})
        except ValidationError as e:
            return ToolResult.fail(f"invalid arguments for '{name}': {e}")
        try:
            return await spec.handler(params, ctx)
        except Exception as e:  # a tool error must not crash the server
            return ToolResult.fail(f"tool '{name}' failed: {e}")
