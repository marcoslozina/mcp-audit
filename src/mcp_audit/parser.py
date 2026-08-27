"""Connects to a target MCP server (stdio or remote HTTP) and extracts its
capability surface.

This module is the foundation that security checks (tool poisoning, Unicode
concealment, rug-pulls, secrets, transport security, etc.) analyze. It does
NOT implement any checks itself — it only performs the MCP handshake and
serializes what the server exposes: tools, resources, and prompts, plus
which transport was used to get there.

Two transports are supported:
  - stdio: spawns a local subprocess and talks JSON-RPC over its pipes
    (`inspect_server`). Always available, no network involved.
  - http: connects to a remote MCP server over Streamable HTTP — the remote
    transport defined by the MCP spec (2025-06-18), replacing the older
    HTTP+SSE transport (`inspect_http_server`). Selected automatically when
    the target looks like an http:// or https:// URL; see `is_url_target`.

`inspect_target` / `inspect_target_sync` dispatch between the two based on
the target string and are what the CLI calls — most callers should use
those rather than picking a transport-specific function directly.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

# Prefixes that mark a target as a remote HTTP endpoint rather than a local
# command to spawn. Checked literally (no urlparse) — anything else is
# treated as a stdio launch command, exactly as before this module gained
# remote-transport support.
_HTTP_PREFIXES = ("http://", "https://")


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
    # Transport used to obtain this snapshot: "stdio" (local subprocess
    # pipes) or "http" (remote Streamable HTTP, MCP spec 2025-06-18). Kept
    # explicit (rather than assumed) so downstream checks that care about
    # transport security (TLS, auth) can key off it honestly.
    transport: str = "stdio"
    # For transport == "http": the exact URL connected to, scheme included
    # (http:// vs https://) — the raw fact transport-security and
    # unauthenticated-discovery checks consume. None for stdio, which has
    # no URL.
    endpoint_url: str | None = None


async def _snapshot_from_session(
    session: ClientSession, *, transport: str, endpoint_url: str | None = None
) -> ServerSnapshot:
    """Runs the initialize/list_tools/list_resources/list_prompts handshake
    against an already-connected `ClientSession` and builds a `ServerSnapshot`.

    Shared by both transports (stdio, http) so the actual MCP protocol
    sequence — and what counts as "the server doesn't support this" vs. a
    real failure — is defined in exactly one place.
    """
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
        transport=transport,
        endpoint_url=endpoint_url,
    )


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
            return await _snapshot_from_session(session, transport="stdio")


def inspect_server_sync(command: str, args: list[str] | None = None) -> ServerSnapshot:
    """Synchronous wrapper around inspect_server, for CLI use."""
    return asyncio.run(inspect_server(command, args))


async def inspect_http_server(url: str) -> ServerSnapshot:
    """Connects to `url` as a remote MCP server over Streamable HTTP (the
    remote transport defined by the MCP spec, 2025-06-18), performs the
    `initialize` handshake, and pulls tools/resources/prompts.

    Deliberately sends no headers of any kind — in particular, no
    `Authorization` header. mcp-audit has no CLI-level way to supply
    credentials today, so every HTTP scan is, by construction, an attempt
    with zero auth material. That's a real limitation for scanning a server
    that legitimately requires auth (the whole handshake will fail and the
    scan reports a connection error rather than findings) — but it's also
    exactly the probe `checks.unauthenticated_discovery` needs: if this
    function returns a snapshot at all, the server just handed out its full
    initialize/list_tools surface to a caller that sent no credentials.

    Args:
        url: The MCP server's HTTP(S) endpoint, e.g. "http://host:port/mcp".

    Returns:
        A ServerSnapshot describing everything the server exposes.
    """
    async with streamable_http_client(url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            return await _snapshot_from_session(session, transport="http", endpoint_url=url)


def inspect_http_server_sync(url: str) -> ServerSnapshot:
    """Synchronous wrapper around inspect_http_server, for CLI use."""
    return asyncio.run(inspect_http_server(url))


def is_url_target(target: str) -> bool:
    """True if `target` looks like a remote HTTP(S) MCP endpoint rather than
    a local command to spawn over stdio."""
    return target.startswith(_HTTP_PREFIXES)


async def inspect_target(command_parts: list[str]) -> ServerSnapshot:
    """Dispatches to the right transport based on what `command_parts[0]`
    looks like — the single entry point the CLI uses for both `inspect` and
    `scan`.

    - If `command_parts[0]` is an http:// or https:// URL, connects over
      Streamable HTTP (`inspect_http_server`). A URL target must be the only
      element: unlike a subprocess command, a remote MCP endpoint has no
      notion of trailing positional arguments, so more than one part here is
      a usage mistake worth failing on loudly rather than silently ignoring.
    - Otherwise, treats `command_parts` as `[executable, *args]` and connects
      over stdio (`inspect_server`), exactly as before this module gained
      remote-transport support.
    """
    if not command_parts:
        raise ValueError("no target given")

    if is_url_target(command_parts[0]):
        if len(command_parts) > 1:
            raise ValueError(
                f"a URL target takes no extra arguments, got: {command_parts[1:]!r}. "
                "Pass just the URL, e.g. -- https://example.com/mcp"
            )
        return await inspect_http_server(command_parts[0])

    command, *args = command_parts
    return await inspect_server(command, args)


def inspect_target_sync(command_parts: list[str]) -> ServerSnapshot:
    """Synchronous wrapper around inspect_target, for CLI use."""
    return asyncio.run(inspect_target(command_parts))
