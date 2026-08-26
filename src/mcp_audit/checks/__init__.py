"""Security checks for mcp-audit.

Each check implements `mcp_audit.checks.base.Check` and is registered in
`ALL_CHECKS` below so `mcp-audit scan` can discover and run all of them
without the CLI needing to know about each one individually.
"""

from __future__ import annotations

from mcp_audit.checks.base import Check, CheckOutcome, Finding, Severity
from mcp_audit.checks.secrets import SecretsCheck
from mcp_audit.checks.transport import TransportCheck
from mcp_audit.checks.unicode_concealment import UnicodeConcealmentCheck

ALL_CHECKS: list[Check] = [
    UnicodeConcealmentCheck(),
    SecretsCheck(),
    TransportCheck(),
]

__all__ = [
    "Check",
    "CheckOutcome",
    "Finding",
    "Severity",
    "ALL_CHECKS",
]
