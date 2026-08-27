"""End-to-end tests for the `mcp-audit` CLI.

Uses subprocess (not click.testing.CliRunner): the CLI does real async
stdio work internally (spawning the target server as a child process via
asyncio.run), and running that inside CliRunner's own process/thread model
is fragile. A real subprocess matches exactly how a user (and the smoke
test workflow) invokes the CLI, so it's the more reliable choice here.

Every invocation gets MCP_AUDIT_BASELINE_DIR pointed at a tmp_path so the
rug-pull check baseline never touches the real developer's home directory.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent


def _run_cli(args: list[str], baseline_dir: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["MCP_AUDIT_BASELINE_DIR"] = str(baseline_dir)
    return subprocess.run(
        [sys.executable, "-m", "mcp_audit.cli", *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_scan_toy_server_exits_zero(tmp_path: Path) -> None:
    result = _run_cli(["scan", "--", sys.executable, "examples/toy_server.py"], baseline_dir=tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


def test_scan_evil_server_exits_one(tmp_path: Path) -> None:
    result = _run_cli(["scan", "--", sys.executable, "examples/evil_server.py"], baseline_dir=tmp_path)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL" in result.stdout


def test_scan_format_json_produces_valid_report(tmp_path: Path) -> None:
    result = _run_cli(
        ["scan", "--format", "json", "--", sys.executable, "examples/toy_server.py"],
        baseline_dir=tmp_path,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["schema_version"] == 1
    assert report["server"]["name"] == "toy-server"
    assert report["exit_code"] == 0


def test_scan_format_json_on_evil_server_reports_findings(tmp_path: Path) -> None:
    result = _run_cli(
        ["scan", "--format", "json", "--", sys.executable, "examples/evil_server.py"],
        baseline_dir=tmp_path,
    )

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["schema_version"] == 1
    assert report["exit_code"] == 1

    critical_findings = [f for f in report["findings"] if f["severity"] == "critical"]
    assert any(f["check_id"] == "unicode-concealment" for f in critical_findings)
