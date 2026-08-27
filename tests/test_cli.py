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


def test_inspect_http_server_url_target(tmp_path: Path, toy_http_server_url: str) -> None:
    result = _run_cli(["inspect", "--", toy_http_server_url], baseline_dir=tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Transport: http" in result.stdout
    assert "add:" in result.stdout


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


def test_scan_plaintext_http_server_reports_transport_and_auth_findings(
    tmp_path: Path, toy_http_server_url: str
) -> None:
    """Real end-to-end HTTP scan (see conftest.toy_http_server_url — a real
    subprocess, no mocking): a target given as a URL after `--` is detected
    automatically and connected to over Streamable HTTP, and both
    HTTP-only checks (transport-security, unauthenticated-discovery) run
    for real instead of reporting not_applicable.
    """
    result = _run_cli(
        ["scan", "--format", "json", "--", toy_http_server_url],
        baseline_dir=tmp_path,
    )

    assert result.returncode == 1, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["server"]["transport"] == "http"

    high_findings = [f for f in report["findings"] if f["severity"] == "high"]
    check_ids = {f["check_id"] for f in high_findings}
    assert "transport-security" in check_ids
    assert "unauthenticated-discovery" in check_ids

    checks_by_id = {c["check_id"]: c for c in report["checks"]}
    assert checks_by_id["transport-security"]["status"] == "ran"
    assert checks_by_id["unauthenticated-discovery"]["status"] == "ran"


def test_scan_authed_http_server_without_credentials_fails_the_handshake(
    tmp_path: Path, toy_http_server_authed_url: str
) -> None:
    """mcp-audit sends no auth headers on a URL target. Against a server
    that correctly requires auth, the whole handshake fails — a structured
    connection-error report, not a false "no findings" pass and not a
    spurious unauthenticated-discovery finding (there's no snapshot for
    that check to run against)."""
    result = _run_cli(
        ["scan", "--format", "json", "--", toy_http_server_authed_url],
        baseline_dir=tmp_path,
    )

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert "error" in report
