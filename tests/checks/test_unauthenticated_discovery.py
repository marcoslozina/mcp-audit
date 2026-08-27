"""Tests for UnauthenticatedDiscoveryCheck.

Unit tests build synthetic ServerSnapshot objects directly (same pattern as
test_transport.py / test_unicode_concealment.py). The real end-to-end proof
that this check's premise holds — mcp-audit's HTTP client genuinely sends
no auth headers, and a snapshot only exists when the server handed out its
surface without any — lives in tests/test_parser_http.py, which performs a
real HTTP round-trip against examples/toy_http_server.py and
examples/toy_http_server_authed.py.
"""

from __future__ import annotations

from mcp_audit.checks.unauthenticated_discovery import UnauthenticatedDiscoveryCheck
from mcp_audit.parser import ServerSnapshot, ToolInfo


def test_stdio_transport_is_not_applicable() -> None:
    snapshot = ServerSnapshot(
        server_name="toy-server",
        server_version="0.1.0",
        protocol_version="2025-06-18",
        transport="stdio",
    )

    outcome = UnauthenticatedDiscoveryCheck().run(snapshot)

    assert outcome.status == "not_applicable"
    assert outcome.findings == []
    assert "stdio" in (outcome.reason or "")


def test_http_snapshot_is_a_high_finding() -> None:
    """A ServerSnapshot with transport="http" only exists in the real code
    path (mcp_audit.parser.inspect_http_server) if the initialize/list_tools
    handshake already succeeded with zero auth headers sent — so its mere
    existence is exactly what this check reports on."""
    snapshot = ServerSnapshot(
        server_name="toy-server",
        server_version="0.1.0",
        protocol_version="2025-06-18",
        transport="http",
        endpoint_url="https://example.com/mcp",
        tools=[ToolInfo(name="add", description="Add two numbers.")],
    )

    outcome = UnauthenticatedDiscoveryCheck().run(snapshot)

    assert outcome.status == "ran"
    assert len(outcome.findings) == 1
    finding = outcome.findings[0]
    assert finding.severity == "high"
    assert finding.check_id == "unauthenticated-discovery"
    assert finding.location == "https://example.com/mcp"
    assert "no authentication" in finding.title.lower()
    # Honesty check: the description must not overclaim beyond what a
    # zero-header probe can actually prove.
    assert "does not rule out" in finding.description


def test_finding_mentions_full_surface_counts() -> None:
    snapshot = ServerSnapshot(
        server_name="toy-server",
        server_version="0.1.0",
        protocol_version="2025-06-18",
        transport="http",
        endpoint_url="http://127.0.0.1:8000/mcp",
        tools=[ToolInfo(name="add", description="d"), ToolInfo(name="sub", description="d")],
    )

    outcome = UnauthenticatedDiscoveryCheck().run(snapshot)

    assert "2 tool(s)" in outcome.findings[0].description
