"""Tests for TransportCheck.

Today mcp-audit only supports stdio, which has no notion of TLS/auth — the
check must honestly report "not_applicable" rather than a false "passed".
"""

from __future__ import annotations

from mcp_audit.checks.transport import TransportCheck
from mcp_audit.parser import ServerSnapshot


def test_stdio_transport_is_not_applicable() -> None:
    snapshot = ServerSnapshot(
        server_name="toy-server",
        server_version="0.1.0",
        protocol_version="2025-06-18",
        transport="stdio",
    )

    outcome = TransportCheck().run(snapshot)

    assert outcome.status == "not_applicable"
    assert outcome.findings == []
    assert "stdio" in (outcome.reason or "")
