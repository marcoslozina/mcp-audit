"""Integration tests for mcp_audit.parser.inspect_server.

These connect to a *real* MCP server (examples/toy_server.py) over a real
stdio subprocess — no mocking. The project already verified this works
manually (see AGENTS.md); this automates that verification.
"""

from __future__ import annotations

from mcp_audit.parser import ServerSnapshot, inspect_server


async def test_inspect_toy_server_returns_snapshot(toy_server_command: list[str]) -> None:
    command, *args = toy_server_command
    snapshot = await inspect_server(command, args)

    assert isinstance(snapshot, ServerSnapshot)
    assert snapshot.server_name == "toy-server"
    assert snapshot.transport == "stdio"
    assert snapshot.protocol_version is not None


async def test_inspect_toy_server_tools(toy_server_command: list[str]) -> None:
    command, *args = toy_server_command
    snapshot = await inspect_server(command, args)

    assert len(snapshot.tools) == 3
    tool_names = {tool.name for tool in snapshot.tools}
    assert tool_names == {"add", "get_weather", "reverse_text"}

    add_tool = next(t for t in snapshot.tools if t.name == "add")
    assert add_tool.description == "Add two numbers together."
    assert "a" in add_tool.input_schema.get("properties", {})
    assert "b" in add_tool.input_schema.get("properties", {})


async def test_inspect_toy_server_resources(toy_server_command: list[str]) -> None:
    command, *args = toy_server_command
    snapshot = await inspect_server(command, args)

    assert len(snapshot.resources) == 1
    resource = snapshot.resources[0]
    assert resource.uri == "toy://readme"


async def test_inspect_toy_server_prompts(toy_server_command: list[str]) -> None:
    command, *args = toy_server_command
    snapshot = await inspect_server(command, args)

    assert len(snapshot.prompts) == 1
    prompt = snapshot.prompts[0]
    assert prompt.name == "greet"
