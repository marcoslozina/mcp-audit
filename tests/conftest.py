"""Shared pytest fixtures for the mcp-audit test suite.

Test isolation note: `RugPullCheck` defaults to storing baselines under the
real `~/.mcp-audit/baselines` (see `mcp_audit.checks.rug_pull`). Any test
that runs the full CLI (which constructs `RugPullCheck` internally) MUST set
the `MCP_AUDIT_BASELINE_DIR` env var to a temp directory first, via the
`baseline_dir_env` fixture below — otherwise the suite would read/write the
real developer's home directory. Unit tests that construct `RugPullCheck`
directly can instead just pass `baseline_dir=tmp_path` and skip this fixture.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"

TOY_SERVER = EXAMPLES_DIR / "toy_server.py"
EVIL_SERVER = EXAMPLES_DIR / "evil_server.py"
TOY_HTTP_SERVER = EXAMPLES_DIR / "toy_http_server.py"
TOY_HTTP_SERVER_AUTHED = EXAMPLES_DIR / "toy_http_server_authed.py"
VULNERABLE_CONFIG = EXAMPLES_DIR / "vulnerable_config.py"

# Must match REQUIRED_TOKEN in examples/toy_http_server_authed.py.
TOY_HTTP_SERVER_AUTHED_TOKEN = "test-only-token-not-a-real-secret"


@pytest.fixture
def toy_server_command() -> list[str]:
    """[command, *args] to launch toy_server.py, using this interpreter
    (not a bare "python" on PATH, which may not exist in every environment)."""
    return [sys.executable, str(TOY_SERVER)]


@pytest.fixture
def evil_server_command() -> list[str]:
    return [sys.executable, str(EVIL_SERVER)]


def _free_port() -> int:
    """Ask the OS for a free TCP port on localhost, the standard
    bind-to-0-then-close trick — good enough for a short-lived test server,
    real races are exceedingly unlikely in a single-machine test run."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_until_accepting_connections(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"server on port {port} did not start accepting connections within {timeout}s")


def _run_http_fixture_server(script: Path) -> Iterator[str]:
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(script), str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_until_accepting_connections(port)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


@pytest.fixture
def toy_http_server_url() -> Iterator[str]:
    """Launches examples/toy_http_server.py (no auth, plain http://) as a
    real subprocess on a free port and yields its MCP endpoint URL. No
    mocking: tests using this fixture perform a real Streamable HTTP
    round-trip."""
    yield from _run_http_fixture_server(TOY_HTTP_SERVER)


@pytest.fixture
def toy_http_server_authed_url() -> Iterator[str]:
    """Same as `toy_http_server_url`, but the server requires
    `Authorization: Bearer <TOY_HTTP_SERVER_AUTHED_TOKEN>` — used to prove
    mcp-audit (which sends no auth headers) gets a real connection failure
    against a server that correctly gates its discovery surface."""
    yield from _run_http_fixture_server(TOY_HTTP_SERVER_AUTHED)


@pytest.fixture
def baseline_dir_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point RugPullCheck's default baseline directory at a temp dir for the
    duration of a test, so nothing touches the real user's home directory.
    """
    baseline_dir = tmp_path / "baselines"
    monkeypatch.setenv("MCP_AUDIT_BASELINE_DIR", str(baseline_dir))
    return baseline_dir
