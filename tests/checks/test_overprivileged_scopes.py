"""Tests for OverprivilegedScopesCheck.

This check has two independent levels (see the module docstring in
`overprivileged_scopes.py`):
  - protocol-level: always runs, using only `tool.description` and
    `tool.input_schema` from the `ServerSnapshot` (no `--source-dir`
    needed).
  - source-level: only runs with `--source-dir`, parsing Python source on
    disk for undisclosed high-privilege calls in MCP tool/resource
    handlers.

Both levels are heuristic and say so in their findings — these tests check
detection and (just as importantly) that clean/ordinary tools like the
ones in `toy_server.py` don't produce false positives.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.overprivileged_scopes import OverprivilegedScopesCheck
from mcp_audit.parser import ServerSnapshot, ToolInfo

REPO_ROOT = Path(__file__).parent.parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"

_DUMMY_SNAPSHOT = ServerSnapshot(server_name="dummy", server_version=None, protocol_version=None)


def _snapshot_with_tools(*tools: ToolInfo) -> ServerSnapshot:
    return ServerSnapshot(
        server_name="test-server", server_version="0.1.0", protocol_version="2025-06-18", tools=list(tools)
    )


# --- Protocol-level: scope-narrowing description + unconstrained param ----


def test_detects_scope_narrowing_description_with_unconstrained_path_param() -> None:
    # Mirrors DVMCP Challenge 3's `read_file(filename)`: description reads
    # as scope-limited ("public directory"), schema places no constraint
    # on the string that actually gets used.
    tool = ToolInfo(
        name="read_file",
        description="Read a file from the public directory.",
        input_schema={"type": "object", "properties": {"filename": {"type": "string"}}},
    )
    snapshot = _snapshot_with_tools(tool)

    outcome = OverprivilegedScopesCheck().run(snapshot, source_dir=None)

    assert outcome.status == "ran"
    matches = [f for f in outcome.findings if f.location == "tool:read_file"]
    assert matches
    assert matches[0].severity == "medium"
    assert "read_file" in matches[0].title


def test_constrained_param_produces_no_scope_narrowing_finding() -> None:
    tool = ToolInfo(
        name="read_file",
        description="Read a file from the public directory.",
        input_schema={
            "type": "object",
            "properties": {"filename": {"type": "string", "enum": ["welcome.txt", "overview.txt"]}},
        },
    )
    snapshot = _snapshot_with_tools(tool)

    outcome = OverprivilegedScopesCheck().run(snapshot, source_dir=None)

    assert outcome.findings == []


def test_toy_server_style_tools_produce_no_findings() -> None:
    # Same tool shapes as examples/toy_server.py — must stay clean, or the
    # smoke test / CLI tests would start failing on a server that isn't
    # doing anything wrong.
    tools = [
        ToolInfo(
            name="add",
            description="Add two numbers together.",
            input_schema={"properties": {"a": {"type": "integer"}, "b": {"type": "integer"}}},
        ),
        ToolInfo(
            name="get_weather",
            description="Return a fake weather report for a city.",
            input_schema={"properties": {"city": {"type": "string"}}},
        ),
        ToolInfo(
            name="reverse_text",
            description="Reverse the characters of the given text.",
            input_schema={"properties": {"text": {"type": "string"}}},
        ),
    ]
    snapshot = _snapshot_with_tools(*tools)

    outcome = OverprivilegedScopesCheck().run(snapshot, source_dir=None)

    assert outcome.status == "ran"
    assert outcome.findings == []


# --- Protocol-level: undisclosed multi-category parameters -----------------


def test_detects_undisclosed_multi_category_parameters() -> None:
    tool = ToolInfo(
        name="do_thing",
        description="Do a thing.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}, "url": {"type": "string"}},
        },
    )
    snapshot = _snapshot_with_tools(tool)

    outcome = OverprivilegedScopesCheck().run(snapshot, source_dir=None)

    matches = [f for f in outcome.findings if f.severity == "low"]
    assert matches
    assert "do_thing" in matches[0].title


def test_disclosed_multi_category_parameters_produce_no_finding() -> None:
    tool = ToolInfo(
        name="fetch_remote_file",
        description="Download a file from a URL over the network and return its path.",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}, "url": {"type": "string"}},
        },
    )
    snapshot = _snapshot_with_tools(tool)

    outcome = OverprivilegedScopesCheck().run(snapshot, source_dir=None)

    assert outcome.findings == []


# --- Source-level -----------------------------------------------------------


def test_detects_undisclosed_privilege_in_vulnerable_fixture() -> None:
    outcome = OverprivilegedScopesCheck().run(_DUMMY_SNAPSHOT, source_dir=EXAMPLES_DIR)

    assert outcome.status == "ran"
    matches = [f for f in outcome.findings if "vulnerable_scope.py" in f.location]
    assert matches, "expected at least one finding in examples/vulnerable_scope.py"
    assert any(f.severity == "medium" for f in matches)
    assert any("check_service_status" in f.title for f in matches)


def test_clean_handler_produces_no_source_level_finding(tmp_path: Path) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text(
        "class _FakeMCP:\n"
        "    def tool(self):\n"
        "        def decorator(func):\n"
        "            return func\n"
        "        return decorator\n"
        "\n"
        "mcp = _FakeMCP()\n"
        "\n"
        "@mcp.tool()\n"
        "def add(a: int, b: int) -> int:\n"
        "    '''Add two numbers together.'''\n"
        "    return a + b\n",
        encoding="utf-8",
    )

    outcome = OverprivilegedScopesCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    assert outcome.findings == []


def test_disclosed_handler_produces_no_source_level_finding(tmp_path: Path) -> None:
    disclosed = tmp_path / "disclosed.py"
    disclosed.write_text(
        "import subprocess\n"
        "\n"
        "class _FakeMCP:\n"
        "    def tool(self):\n"
        "        def decorator(func):\n"
        "            return func\n"
        "        return decorator\n"
        "\n"
        "mcp = _FakeMCP()\n"
        "\n"
        "@mcp.tool()\n"
        "def run_shell_command(command: str) -> str:\n"
        "    '''Execute a shell command and return its output.'''\n"
        "    return subprocess.check_output(command, shell=True).decode()\n",
        encoding="utf-8",
    )

    outcome = OverprivilegedScopesCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    assert outcome.findings == []


def test_no_source_dir_still_runs_protocol_level_only() -> None:
    outcome = OverprivilegedScopesCheck().run(_DUMMY_SNAPSHOT, source_dir=None)

    assert outcome.status == "ran"
    assert outcome.findings == []
    assert "protocol-level only" in (outcome.reason or "")


def test_missing_source_dir_still_reports_protocol_level_ran(tmp_path: Path) -> None:
    outcome = OverprivilegedScopesCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path / "does-not-exist")

    assert outcome.status == "ran"
    assert "does not exist" in (outcome.reason or "")


def test_non_python_source_dir_notes_no_source_level_analysis(tmp_path: Path) -> None:
    (tmp_path / "server.rb").write_text("puts 'hello'\n", encoding="utf-8")

    outcome = OverprivilegedScopesCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    assert "Python" in (outcome.reason or "")
