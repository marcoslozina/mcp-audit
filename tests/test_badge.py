"""End-to-end tests for the `mcp-audit badge` command.

Same subprocess-based approach as `tests/test_cli.py` (see that file's
docstring for why): the CLI does real async stdio work internally, so a
real subprocess is the reliable way to exercise it end-to-end.
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


def test_badge_toy_server_is_brightgreen_and_passing(tmp_path: Path) -> None:
    result = _run_cli(["badge", "--", sys.executable, "examples/toy_server.py"], baseline_dir=tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    badge = json.loads(result.stdout)
    assert badge == {
        "schemaVersion": 1,
        "label": "mcp-audit",
        "message": "passing",
        "color": "brightgreen",
    }


def test_badge_evil_server_is_red_and_exits_one(tmp_path: Path) -> None:
    result = _run_cli(["badge", "--", sys.executable, "examples/evil_server.py"], baseline_dir=tmp_path)

    assert result.returncode == 1, result.stdout + result.stderr
    badge = json.loads(result.stdout)
    assert badge["schemaVersion"] == 1
    assert badge["label"] == "mcp-audit"
    assert badge["color"] == "red"
    assert "critical/high" in badge["message"]
