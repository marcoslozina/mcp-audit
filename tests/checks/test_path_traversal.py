"""Tests for PathTraversalCheck.

PathTraversalCheck inspects source code on disk (via --source-dir), not the
MCP protocol surface, so the ServerSnapshot passed to `run()` is irrelevant
to its logic — a minimal placeholder is enough.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.path_traversal import PathTraversalCheck
from mcp_audit.parser import ServerSnapshot

REPO_ROOT = Path(__file__).parent.parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"

_DUMMY_SNAPSHOT = ServerSnapshot(server_name="dummy", server_version=None, protocol_version=None)

_FAKE_MCP_PREAMBLE = (
    "class _FakeMCP:\n"
    "    def tool(self):\n"
    "        def decorator(func):\n"
    "            return func\n"
    "        return decorator\n"
    "\n"
    "    def resource(self, *args, **kwargs):\n"
    "        return self.tool()\n"
    "\n"
    "mcp = _FakeMCP()\n"
    "\n"
)


def test_detects_path_traversal_in_vulnerable_fixture() -> None:
    outcome = PathTraversalCheck().run(_DUMMY_SNAPSHOT, source_dir=EXAMPLES_DIR)

    assert outcome.status == "ran"
    matches = [f for f in outcome.findings if "vulnerable_path_traversal.py" in f.location]
    assert matches, "expected at least one finding in examples/vulnerable_path_traversal.py"
    assert matches[0].severity == "high"
    assert "read_report" in matches[0].title


def test_detects_direct_parameter_reaching_open(tmp_path: Path) -> None:
    vulnerable = tmp_path / "vulnerable.py"
    vulnerable.write_text(
        _FAKE_MCP_PREAMBLE + "import os\n"
        "\n"
        "@mcp.tool()\n"
        "def read_file(filename: str) -> str:\n"
        "    if os.path.exists(filename):\n"
        "        with open(filename, 'r') as f:\n"
        "            return f.read()\n"
        "    return ''\n",
        encoding="utf-8",
    )

    outcome = PathTraversalCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    assert len(outcome.findings) == 1
    assert outcome.findings[0].severity == "high"
    assert "read_file" in outcome.findings[0].title


def test_ignores_non_handler_functions(tmp_path: Path) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text(
        "def read_file(filename: str) -> str:\n    with open(filename, 'r') as f:\n        return f.read()\n",
        encoding="utf-8",
    )

    outcome = PathTraversalCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    assert outcome.findings == []


def test_sanitized_handler_produces_no_findings(tmp_path: Path) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text(
        _FAKE_MCP_PREAMBLE + "import os\n"
        "\n"
        "BASE_DIR = '/srv/reports'\n"
        "\n"
        "@mcp.tool()\n"
        "def read_report(filename: str) -> str:\n"
        "    candidate = os.path.realpath(os.path.join(BASE_DIR, filename))\n"
        "    if not candidate.startswith(os.path.realpath(BASE_DIR)):\n"
        "        raise ValueError('access denied')\n"
        "    with open(candidate, 'r') as f:\n"
        "        return f.read()\n",
        encoding="utf-8",
    )

    outcome = PathTraversalCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    assert outcome.findings == []


def test_no_source_dir_is_skipped_not_silently_passed() -> None:
    outcome = PathTraversalCheck().run(_DUMMY_SNAPSHOT, source_dir=None)

    assert outcome.status == "skipped"
    assert outcome.findings == []


def test_missing_source_dir_is_skipped(tmp_path: Path) -> None:
    outcome = PathTraversalCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path / "does-not-exist")

    assert outcome.status == "skipped"
    assert outcome.findings == []


def test_non_python_source_dir_is_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "server.rb").write_text("puts 'hello'\n", encoding="utf-8")

    outcome = PathTraversalCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "not_applicable"
    assert outcome.findings == []
    assert "Python" in (outcome.reason or "")
