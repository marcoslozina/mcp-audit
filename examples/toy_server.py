"""Minimal toy MCP server used to exercise mcp_audit's parser end-to-end.

Exposes three trivial tools, one resource and one prompt over stdio so
`mcp-audit inspect` has something real to talk to. Not meant to be secure
or realistic — it's purely a fixture for testing the parsing foundation.

Run standalone:
    python examples/toy_server.py

Inspect it with mcp-audit:
    uv run mcp-audit inspect -- python examples/toy_server.py
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

server = MCPServer("toy-server")


@server.tool()
def add(a: int, b: int) -> int:
    """Add two numbers together."""
    return a + b


@server.tool()
def get_weather(city: str) -> str:
    """Return a fake weather report for a city."""
    return f"The weather in {city} is sunny, 24C (fake data, for testing only)."


@server.tool()
def reverse_text(text: str) -> str:
    """Reverse the characters of the given text."""
    return text[::-1]


@server.resource("toy://readme")
def readme() -> str:
    """A tiny static resource, exposed just to prove resource listing works."""
    return "This is a toy MCP server used to test mcp-audit's parser."


@server.prompt()
def greet(name: str) -> str:
    """A tiny sample prompt template."""
    return f"Please greet {name} warmly."


if __name__ == "__main__":
    server.run(transport="stdio")
