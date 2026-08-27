"""Integration tests for the HTTP (Streamable HTTP) side of mcp_audit.parser.

These connect to a *real* MCP server (examples/toy_http_server.py) over a
real HTTP subprocess — no mocking — mirroring test_parser.py's approach for
stdio. See tests/conftest.py for the `toy_http_server_url` /
`toy_http_server_authed_url` fixtures.
"""

from __future__ import annotations

import pytest

from mcp_audit.parser import (
    ServerSnapshot,
    inspect_http_server,
    inspect_target,
    is_url_target,
)


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("http://example.com/mcp", True),
        ("https://example.com/mcp", True),
        ("python", False),
        ("examples/toy_server.py", False),
        ("./http-server-launcher", False),
    ],
)
def test_is_url_target(target: str, expected: bool) -> None:
    assert is_url_target(target) is expected


async def test_inspect_http_server_returns_snapshot(toy_http_server_url: str) -> None:
    snapshot = await inspect_http_server(toy_http_server_url)

    assert isinstance(snapshot, ServerSnapshot)
    assert snapshot.server_name == "toy-server"
    assert snapshot.transport == "http"
    assert snapshot.endpoint_url == toy_http_server_url
    assert snapshot.protocol_version is not None


async def test_inspect_http_server_tools(toy_http_server_url: str) -> None:
    snapshot = await inspect_http_server(toy_http_server_url)

    assert len(snapshot.tools) == 3
    tool_names = {tool.name for tool in snapshot.tools}
    assert tool_names == {"add", "get_weather", "reverse_text"}


async def test_inspect_http_server_resources_and_prompts(toy_http_server_url: str) -> None:
    snapshot = await inspect_http_server(toy_http_server_url)

    assert len(snapshot.resources) == 1
    assert snapshot.resources[0].uri == "toy://readme"
    assert len(snapshot.prompts) == 1
    assert snapshot.prompts[0].name == "greet"


async def test_inspect_target_dispatches_url_to_http(toy_http_server_url: str) -> None:
    snapshot = await inspect_target([toy_http_server_url])

    assert snapshot.transport == "http"
    assert snapshot.endpoint_url == toy_http_server_url


async def test_inspect_target_rejects_extra_args_on_url_target(toy_http_server_url: str) -> None:
    with pytest.raises(ValueError, match="takes no extra arguments"):
        await inspect_target([toy_http_server_url, "unexpected-extra-arg"])


async def test_inspect_http_server_fails_without_auth_against_authed_server(
    toy_http_server_authed_url: str,
) -> None:
    """mcp-audit's HTTP client sends no auth headers by design (see
    parser.inspect_http_server's docstring). Against a server that
    correctly requires auth, that means the handshake itself must fail —
    not silently return a partial/empty snapshot.
    """
    with pytest.raises(Exception):  # noqa: B017,PT011 - any failure proves the point; exact type is httpx/anyio-internal
        await inspect_http_server(toy_http_server_authed_url)
