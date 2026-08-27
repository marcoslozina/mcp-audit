"""Tests for TransportCheck.

For a stdio target, there is no notion of TLS — the check must honestly
report "not_applicable" rather than a false "passed". For an http(s)
target, it runs for real: https:// passes clean, http:// is a finding.
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


def test_plaintext_http_is_a_high_finding() -> None:
    snapshot = ServerSnapshot(
        server_name="toy-server",
        server_version="0.1.0",
        protocol_version="2025-06-18",
        transport="http",
        endpoint_url="http://127.0.0.1:8000/mcp",
    )

    outcome = TransportCheck().run(snapshot)

    assert outcome.status == "ran"
    assert len(outcome.findings) == 1
    finding = outcome.findings[0]
    assert finding.severity == "high"
    assert finding.check_id == "transport-security"
    assert finding.location == "http://127.0.0.1:8000/mcp"
    assert "plaintext" in finding.title.lower()


def test_https_is_clean() -> None:
    snapshot = ServerSnapshot(
        server_name="toy-server",
        server_version="0.1.0",
        protocol_version="2025-06-18",
        transport="http",
        endpoint_url="https://example.com/mcp",
    )

    outcome = TransportCheck().run(snapshot)

    assert outcome.status == "ran"
    assert outcome.findings == []
