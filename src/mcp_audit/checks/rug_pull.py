"""Check: rug-pull detection — tool definitions drifting after initial trust.

A "rug-pull" in the MCP threat model is not a static property of a single
snapshot the way a hardcoded secret or a Unicode payload is — it's a
*temporal* property: a server behaves one way when a human approves it, then
changes what a tool actually does (or claims to do) on a later connection,
after that approval has already been granted and the human has stopped
re-reading the fine print. Detecting it therefore requires comparing the
current snapshot against a previously recorded one, not just inspecting the
current snapshot in isolation the way every other check in this package
does.

Design:

  - Each target server is identified by a "server-id": either an explicit
    name the operator passes via `--server-id` (recommended — stable across
    moving the server, renaming files, changing argv order), or, if omitted,
    a SHA-256 hash of the literal launch command (`compute_default_server_id`)
    so repeated scans of the same command still land on the same baseline
    without requiring the operator to name anything.
  - Baselines are stored one-per-server-id as JSON under
    `~/.mcp-audit/baselines/<server-id>.json` (see DEFAULT_BASELINE_DIR).
    Home-directory rather than project-local: mcp-audit scans arbitrary
    target servers from wherever the operator happens to be running the CLI,
    and a baseline keyed to "this server I've approved" should survive the
    operator's cwd changing, not live inside whatever directory they
    happened to be standing in the first time they ran a scan. This default
    can be overridden with the `MCP_AUDIT_BASELINE_DIR` env var (see
    `_resolve_default_baseline_dir`) or the `baseline_dir` constructor
    argument — chiefly so the test suite never touches a real user's home
    directory.
  - Only tool definitions (name + description + input_schema) are
    fingerprinted and diffed today. Resources/prompts can drift the same way
    in principle, but tools are where MCP's actual attack surface lives
    (they're what an agent invokes), so v1 scopes to tools and says so
    honestly via the CheckOutcome.reason rather than silently pretending to
    cover more than it does.

Comparison outcomes, by design:
  - No baseline exists yet for this server-id: create one from the current
    snapshot and report it as informational (CheckOutcome.reason), NOT as a
    Finding — there is nothing to compare against on a first run, and
    treating "first run" as a security finding would be dishonest noise.
  - `--update-baseline` passed: unconditionally overwrite the baseline with
    the current snapshot and skip comparison. This is the operator's way of
    saying "I reviewed this change and it's legitimate" after a real
    Finding was raised on a previous run.
  - Baseline exists and no `--update-baseline`: diff tool-by-tool.
      * description or input_schema changed for an existing tool -> "high"
        (the actual rug-pull signature: behavior changing under a name the
        user already trusts).
      * a tool name appears that wasn't in the baseline -> "medium",
        informational (new capability, not necessarily malicious, but
        worth a fresh look).
      * a tool name from the baseline is now missing -> "low",
        informational (shrinking the surface isn't itself a risk).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_audit.checks.base import Check, CheckOutcome, Finding
from mcp_audit.parser import ServerSnapshot, ToolInfo

CHECK_ID = "rug-pull-detection"

# Env var name a caller (chiefly: the test suite) can set to override where
# baselines are read/written, instead of the real user's home directory.
# Without this, running the test suite would read and write JSON files under
# the real ~/.mcp-audit/baselines of whoever runs `pytest` — a test
# isolation bug (and, more generally, a test suite should never touch the
# real system of the person running it). Production behavior is unaffected
# unless this is explicitly set.
_BASELINE_DIR_ENV_VAR = "MCP_AUDIT_BASELINE_DIR"

# Home-directory, not project-local: see module docstring for why. Computed
# once at import time for display/backward-compat purposes (e.g. anything
# that imports this constant directly); RugPullCheck itself re-resolves the
# default at construction time via `_resolve_default_baseline_dir()` below,
# so tests can override it per-run (e.g. via monkeypatch.setenv) without
# needing to reload this module.
DEFAULT_BASELINE_DIR = Path.home() / ".mcp-audit" / "baselines"


def _resolve_default_baseline_dir() -> Path:
    """Resolve the baseline directory to use when the caller didn't pass one
    explicitly.

    Honors `MCP_AUDIT_BASELINE_DIR` if set (test suites / advanced use),
    falling back to the real `~/.mcp-audit/baselines` otherwise. Checked at
    `RugPullCheck.__init__` time rather than only once at import, so this
    works regardless of import order.
    """
    override = os.environ.get(_BASELINE_DIR_ENV_VAR)
    if override:
        return Path(override)
    return DEFAULT_BASELINE_DIR


def compute_default_server_id(command: str, args: list[str]) -> str:
    """Derive a stable, filesystem-safe server-id from a launch command.

    Used as the fallback when the operator doesn't pass --server-id. Hashing
    (rather than e.g. slugifying the raw command) avoids filename-safety
    issues with arbitrary paths/flags and keeps baseline filenames short and
    uniform regardless of how verbose the launch command is.
    """
    raw = " ".join([command, *args])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _canonical_schema(schema: dict[str, Any] | None) -> str:
    """Order-independent string form of a JSON schema, for equality checks
    and for embedding in human-readable diffs."""
    return json.dumps(schema or {}, sort_keys=True)


@dataclass
class _ToolFingerprint:
    name: str
    description: str | None
    input_schema: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> _ToolFingerprint:
        return cls(
            name=data["name"],
            description=data.get("description"),
            input_schema=data.get("input_schema") or {},
        )

    @classmethod
    def from_tool(cls, tool: ToolInfo) -> _ToolFingerprint:
        return cls(name=tool.name, description=tool.description, input_schema=tool.input_schema or {})


class RugPullCheck(Check):
    """Compares the current tool surface against a saved baseline.

    Unlike the other checks in this package, this one needs information the
    ABC's `run(snapshot, source_dir)` signature doesn't carry (which server
    is this, should the baseline be overwritten), so those are constructor
    arguments instead of static per-module state. Callers (currently only
    `mcp_audit.cli.scan`) construct one instance per invocation with the
    resolved server-id, rather than this class being pre-instantiated in
    `checks.ALL_CHECKS` like the stateless checks.
    """

    check_id = CHECK_ID
    name = "Rug-pull detection (tool definition drift)"

    def __init__(
        self,
        server_id: str,
        baseline_dir: Path | None = None,
        update_baseline: bool = False,
    ) -> None:
        self.server_id = server_id
        self.baseline_dir = Path(baseline_dir) if baseline_dir else _resolve_default_baseline_dir()
        self.update_baseline = update_baseline

    def _baseline_path(self) -> Path:
        return self.baseline_dir / f"{self.server_id}.json"

    def _write_baseline(self, path: Path, snapshot: ServerSnapshot, tools: list[_ToolFingerprint]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.now(UTC).isoformat()
        created_at = now
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                created_at = existing.get("created_at", now)
            except (OSError, json.JSONDecodeError):
                pass
        payload = {
            "server_id": self.server_id,
            "server_name": snapshot.server_name,
            "created_at": created_at,
            "updated_at": now,
            "tools": [t.to_dict() for t in tools],
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _load_baseline(self, path: Path) -> list[_ToolFingerprint]:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [_ToolFingerprint.from_dict(t) for t in data.get("tools", [])]

    def run(self, snapshot: ServerSnapshot, source_dir: Path | None = None) -> CheckOutcome:
        baseline_path = self._baseline_path()
        current_tools = [_ToolFingerprint.from_tool(t) for t in snapshot.tools]

        if self.update_baseline:
            self._write_baseline(baseline_path, snapshot, current_tools)
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="ran",
                reason=(
                    f"--update-baseline was passed; baseline for server-id "
                    f"'{self.server_id}' was forcibly overwritten with the current "
                    f"snapshot at {baseline_path}. No comparison performed this run — "
                    "the operator is asserting the current tool definitions are trusted."
                ),
                findings=[],
            )

        if not baseline_path.exists():
            self._write_baseline(baseline_path, snapshot, current_tools)
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="ran",
                reason=(
                    f"no baseline existed for server-id '{self.server_id}'; baseline "
                    f"created at {baseline_path} from this run's snapshot "
                    f"({len(current_tools)} tool(s)). Nothing to compare yet — this is "
                    "the first time mcp-audit has seen this server. Re-run mcp-audit "
                    "scan later against the same --server-id to detect drift."
                ),
                findings=[],
            )

        previous_tools = self._load_baseline(baseline_path)
        findings = self._diff(previous_tools, current_tools)

        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            reason=(
                f"compared current snapshot against existing baseline for "
                f"server-id '{self.server_id}' at {baseline_path} "
                f"({len(previous_tools)} tool(s) in baseline, {len(current_tools)} tool(s) now)."
            ),
            findings=findings,
        )

    def _diff(self, previous: list[_ToolFingerprint], current: list[_ToolFingerprint]) -> list[Finding]:
        findings: list[Finding] = []
        previous_by_name = {t.name: t for t in previous}
        current_by_name = {t.name: t for t in current}

        for name, curr in current_by_name.items():
            prev = previous_by_name.get(name)
            if prev is None:
                findings.append(
                    Finding(
                        severity="medium",
                        check_id=self.check_id,
                        title=f"New tool added since baseline: '{name}'",
                        description=(
                            f"Tool '{name}' was not present in the baseline snapshot and "
                            "now appears in this server's tool list. Not necessarily "
                            "malicious, but any new capability granted by a "
                            "previously-approved server deserves a fresh look before use."
                        ),
                        location=f"tool:{name}",
                    )
                )
                continue

            desc_changed = prev.description != curr.description
            schema_changed = _canonical_schema(prev.input_schema) != _canonical_schema(curr.input_schema)
            if not (desc_changed or schema_changed):
                continue

            change_notes: list[str] = []
            if desc_changed:
                change_notes.append(f"description changed from {prev.description!r} to {curr.description!r}")
            if schema_changed:
                change_notes.append(
                    "input_schema changed from "
                    f"{_canonical_schema(prev.input_schema)} to "
                    f"{_canonical_schema(curr.input_schema)}"
                )

            findings.append(
                Finding(
                    severity="high",
                    check_id=self.check_id,
                    title=f"Tool '{name}' definition changed since baseline (possible rug-pull)",
                    description=(
                        f"Tool '{name}' was previously approved with a different "
                        "definition. A tool's description or input schema changing "
                        "after a user has already trusted it is the classic rug-pull "
                        "pattern: capability granted under one description can "
                        "silently become something else. " + "; ".join(change_notes)
                    ),
                    location=f"tool:{name}",
                )
            )

        for name in previous_by_name:
            if name not in current_by_name:
                findings.append(
                    Finding(
                        severity="low",
                        check_id=self.check_id,
                        title=f"Tool removed since baseline: '{name}'",
                        description=(
                            f"Tool '{name}' was present in the baseline snapshot but is "
                            "no longer exposed by this server. Informational — removing "
                            "a tool is not itself a security risk, but it changes the "
                            "server's previously-approved surface."
                        ),
                        location=f"tool:{name}",
                    )
                )

        return findings
