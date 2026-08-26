"""Connects to a target MCP server over stdio and extracts its capability surface.

This module is the foundation that future security checks (tool poisoning,
Unicode concealment, rug-pulls, secrets, etc.) will analyze. It does NOT
implement any checks itself — it only performs the MCP handshake and
serializes what the server exposes: tools, resources, and prompts.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@dataclass
class ToolInfo:
    """A single tool exposed by an MCP server."""

    name: str
    description: str | None
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceInfo:
    """A single resource exposed by an MCP server."""

    uri: str
    name: str | None
    description: str | None
    mime_type: str | None


@dataclass
class PromptInfo:
    """A single prompt exposed by an MCP server."""

    name: str
    description: str | None
    arguments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ServerSnapshot:
    """Serializable snapshot of everything a target MCP server exposes.

    This is the artifact that downstream security checks (not implemented
    yet) will consume as input.
    """

    server_name: str
    server_version: str | None
    protocol_version: str | None
    tools: list[ToolInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    prompts: list[PromptInfo] = field(default_factory=list)


async def inspect_server(command: str, args: list[str] | None = None) -> ServerSnapshot:
    """Spawns `command` as an MCP server over stdio, performs the `initialize`
    handshake, and pulls tools/resources/prompts.

    Args:
        command: Executable to launch the target MCP server (e.g. "python").
        args: Arguments to pass to the executable (e.g. ["toy_server.py"]).

    Returns:
        A ServerSnapshot describing everything the server exposes.
    """
    server_params = StdioServerParameters(command=command, args=args or [])

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()

            tools_result = await session.list_tools()
            tools = [
                ToolInfo(
                    name=tool.name,
                    description=tool.description,
                    input_schema=tool.input_schema or {},
                )
                for tool in tools_result.tools
            ]

            resources: list[ResourceInfo] = []
            try:
                resources_result = await session.list_resources()
                resources = [
                    ResourceInfo(
                        uri=str(resource.uri),
                        name=resource.name,
                        description=resource.description,
                        mime_type=resource.mime_type,
                    )
                    for resource in resources_result.resources
                ]
            except Exception:
                # Server doesn't support/expose resources — that's fine.
                pass

            prompts: list[PromptInfo] = []
            try:
                prompts_result = await session.list_prompts()
                prompts = [
                    PromptInfo(
                        name=prompt.name,
                        description=prompt.description,
                        arguments=[arg.model_dump() for arg in (prompt.arguments or [])],
                    )
                    for prompt in prompts_result.prompts
                ]
            except Exception:
                # Server doesn't support/expose prompts — that's fine.
                pass

            return ServerSnapshot(
                server_name=init_result.server_info.name,
                server_version=init_result.server_info.version,
                protocol_version=init_result.protocol_version,
                tools=tools,
                resources=resources,
                prompts=prompts,
            )


def inspect_server_sync(command: str, args: list[str] | None = None) -> ServerSnapshot:
    """Synchronous wrapper around inspect_server, for CLI use."""
    return asyncio.run(inspect_server(command, args))
