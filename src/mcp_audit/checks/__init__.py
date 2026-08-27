"""Security checks for mcp-audit.

Each check implements `mcp_audit.checks.base.Check`. Stateless checks (ones
that only need the snapshot itself) are pre-instantiated and registered in
`ALL_CHECKS` below so `mcp-audit scan` can discover and run all of them
without the CLI needing to know about each one individually.

`RugPullCheck` is the one exception: it needs a server-id resolved from CLI
input (and optionally an `--update-baseline` flag) before it can be
constructed, so it is instantiated per-invocation by `mcp_audit.cli.scan`
instead of living in `ALL_CHECKS`. It's still exported from this package so
the CLI doesn't need to import from the submodule directly.
"""

from __future__ import annotations

from mcp_audit.checks.base import Check, CheckOutcome, Finding, Severity
from mcp_audit.checks.code_injection import CodeInjectionCheck
from mcp_audit.checks.cross_tool_shadowing import CrossToolShadowingCheck
from mcp_audit.checks.overprivileged_scopes import OverprivilegedScopesCheck
from mcp_audit.checks.path_traversal import PathTraversalCheck
from mcp_audit.checks.resource_limits import ResourceLimitsCheck
from mcp_audit.checks.rug_pull import (
    DEFAULT_BASELINE_DIR,
    RugPullCheck,
    compute_default_server_id,
)
from mcp_audit.checks.secrets import SecretsCheck
from mcp_audit.checks.tool_poisoning import ToolPoisoningCheck
from mcp_audit.checks.transport import TransportCheck
from mcp_audit.checks.unauthenticated_discovery import UnauthenticatedDiscoveryCheck
from mcp_audit.checks.unicode_concealment import UnicodeConcealmentCheck

ALL_CHECKS: list[Check] = [
    UnicodeConcealmentCheck(),
    ToolPoisoningCheck(),
    CrossToolShadowingCheck(),
    SecretsCheck(),
    CodeInjectionCheck(),
    PathTraversalCheck(),
    OverprivilegedScopesCheck(),
    ResourceLimitsCheck(),
    TransportCheck(),
    UnauthenticatedDiscoveryCheck(),
]

__all__ = [
    "Check",
    "CheckOutcome",
    "Finding",
    "Severity",
    "ALL_CHECKS",
    "RugPullCheck",
    "compute_default_server_id",
    "DEFAULT_BASELINE_DIR",
]
