"""Tests for ResourceLimitsCheck.

Protocol level always runs (no --source-dir needed), and today always
reports NOT_APPLICABLE — the MCP spec (verified, see the check's module
docstring) has no standardized mechanism for a server to declare a rate
limit, quota, or budget. Source level (--source-dir, Python only) is a
low-confidence heuristic for known rate-limiting library/decorator usage.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.resource_limits import ResourceLimitsCheck
from mcp_audit.parser import ServerSnapshot, ToolInfo

REPO_ROOT = Path(__file__).parent.parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"

_DUMMY_SNAPSHOT = ServerSnapshot(server_name="dummy", server_version=None, protocol_version=None)

_HANDLER_PREAMBLE = (
    "class _FakeMCP:\n"
    "    def tool(self):\n"
    "        def decorator(func):\n"
    "            return func\n"
    "        return decorator\n"
    "\n"
    "mcp = _FakeMCP()\n"
    "\n"
)


# --- Protocol level ----------------------------------------------------------


def test_no_source_dir_is_not_applicable_structural_gap() -> None:
    outcome = ResourceLimitsCheck().run(_DUMMY_SNAPSHOT, source_dir=None)

    assert outcome.status == "not_applicable"
    assert outcome.findings == []
    assert "no standardized mechanism" in (outcome.reason or "")


def test_declared_limit_hint_is_reported_informationally() -> None:
    tool = ToolInfo(
        name="call_api",
        description="Call the API.",
        input_schema={"type": "object", "properties": {}, "x-rate-limit": "10/minute"},
    )
    snapshot = ServerSnapshot(server_name="s", server_version=None, protocol_version=None, tools=[tool])

    outcome = ResourceLimitsCheck().run(snapshot, source_dir=None)

    assert outcome.status == "ran"
    assert outcome.findings == []
    assert "call_api" in (outcome.reason or "")


# --- Source level ------------------------------------------------------------


def test_detects_missing_rate_limiting_in_vulnerable_fixture() -> None:
    outcome = ResourceLimitsCheck().run(_DUMMY_SNAPSHOT, source_dir=EXAMPLES_DIR)

    assert outcome.status == "ran"
    matches = [f for f in outcome.findings if "vulnerable_resource_limits.py" in f.location]
    assert matches, "expected at least one finding in examples/vulnerable_resource_limits.py"
    assert matches[0].severity == "low"
    assert "call_translation_api" in matches[0].title


def test_file_with_limiter_marker_produces_no_finding(tmp_path: Path) -> None:
    limited = tmp_path / "limited.py"
    limited.write_text(
        "from slowapi import Limiter\n"
        "\n" + _HANDLER_PREAMBLE + "import requests\n"
        "\n"
        "@mcp.tool()\n"
        "def call_api(query: str) -> str:\n"
        "    '''Call an external API.'''\n"
        "    return requests.get('https://api.example.com', params={'q': query}).text\n",
        encoding="utf-8",
    )

    outcome = ResourceLimitsCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    assert outcome.findings == []


def test_handler_with_no_external_calls_produces_no_finding(tmp_path: Path) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text(
        _HANDLER_PREAMBLE
        + "@mcp.tool()\ndef add(a: int, b: int) -> int:\n    '''Add two numbers.'''\n    return a + b\n",
        encoding="utf-8",
    )

    outcome = ResourceLimitsCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    assert outcome.findings == []


def test_missing_source_dir_is_skipped(tmp_path: Path) -> None:
    outcome = ResourceLimitsCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path / "does-not-exist")

    assert outcome.status == "skipped"
    assert outcome.findings == []


def test_non_python_source_dir_is_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "server.rb").write_text("puts 'hello'\n", encoding="utf-8")

    outcome = ResourceLimitsCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "not_applicable"
    assert outcome.findings == []
    assert "Python" in (outcome.reason or "")
