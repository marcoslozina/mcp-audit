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

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"

TOY_SERVER = EXAMPLES_DIR / "toy_server.py"
EVIL_SERVER = EXAMPLES_DIR / "evil_server.py"
VULNERABLE_CONFIG = EXAMPLES_DIR / "vulnerable_config.py"


@pytest.fixture
def toy_server_command() -> list[str]:
    """[command, *args] to launch toy_server.py, using this interpreter
    (not a bare "python" on PATH, which may not exist in every environment)."""
    return [sys.executable, str(TOY_SERVER)]


@pytest.fixture
def evil_server_command() -> list[str]:
    return [sys.executable, str(EVIL_SERVER)]


@pytest.fixture
def baseline_dir_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point RugPullCheck's default baseline directory at a temp dir for the
    duration of a test, so nothing touches the real user's home directory.
    """
    baseline_dir = tmp_path / "baselines"
    monkeypatch.setenv("MCP_AUDIT_BASELINE_DIR", str(baseline_dir))
    return baseline_dir
