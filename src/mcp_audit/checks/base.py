"""Shared types for mcp-audit security checks.

A "check" inspects a `ServerSnapshot` (and, optionally, a directory of
server source code on disk) and reports what it found as a list of
`Finding`s, plus an honest `CheckOutcome` describing whether it actually
ran, was skipped, or does not apply to the current scan.

Reporting coverage honestly (what ran vs. what didn't, and why) is a
product requirement, not an afterthought: a security tool that silently
treats "didn't check" the same as "checked, found nothing" is lying to
its user by omission.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from mcp_audit.parser import ServerSnapshot

Severity = Literal["critical", "high", "medium", "low"]
CheckStatus = Literal["ran", "not_applicable", "skipped"]


@dataclass
class Finding:
    """A single security observation produced by a check."""

    severity: Severity
    check_id: str
    title: str
    description: str
    location: str


@dataclass
class CheckOutcome:
    """The result of running (or not running) a single check.

    `status` is the honesty mechanism:
      - "ran": the check executed its full logic against real input.
      - "not_applicable": the check's precondition isn't met by this scan
        (e.g. a transport-security check when the server was inspected
        over stdio, which has no notion of TLS/auth). This is NOT the
        same as "passed" — nothing was verified either way.
      - "skipped": the check could have run in principle but the user
        didn't provide what it needed (e.g. --source-dir for the secrets
        check). Distinct from not_applicable because the user *can* fix
        this by re-running with more input.
    """

    check_id: str
    name: str
    status: CheckStatus
    reason: str | None = None
    findings: list[Finding] = field(default_factory=list)


class Check(ABC):
    """Base class for a single security check."""

    check_id: str
    name: str

    @abstractmethod
    def run(self, snapshot: ServerSnapshot, source_dir: Path | None = None) -> CheckOutcome:
        """Run this check.

        Args:
            snapshot: The parsed capability surface of the target server.
            source_dir: Optional path to the target server's source code,
                for checks that need to inspect code rather than (or in
                addition to) runtime protocol data.
        """
        raise NotImplementedError
