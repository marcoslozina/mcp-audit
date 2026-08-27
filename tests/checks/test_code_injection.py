"""Tests for CodeInjectionCheck.

CodeInjectionCheck wraps bandit and inspects source code on disk (via
--source-dir), not the MCP protocol surface, so the ServerSnapshot passed
to `run()` is irrelevant to its logic — a minimal placeholder is enough.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.code_injection import CodeInjectionCheck
from mcp_audit.parser import ServerSnapshot

REPO_ROOT = Path(__file__).parent.parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"

_DUMMY_SNAPSHOT = ServerSnapshot(server_name="dummy", server_version=None, protocol_version=None)


def test_detects_shell_injection_in_vulnerable_command() -> None:
    outcome = CodeInjectionCheck().run(_DUMMY_SNAPSHOT, source_dir=EXAMPLES_DIR)

    assert outcome.status == "ran"
    matches = [f for f in outcome.findings if "vulnerable_command.py" in f.location]
    assert matches, "expected at least one finding in examples/vulnerable_command.py"
    assert any(f.severity == "critical" for f in matches)
    assert any("B602" in f.title for f in matches)


def test_detects_eval_and_exec(tmp_path: Path) -> None:
    vulnerable = tmp_path / "vulnerable.py"
    vulnerable.write_text(
        "def run_eval(expr: str):\n    return eval(expr)\n\ndef run_exec(code: str) -> None:\n    exec(code)\n",
        encoding="utf-8",
    )

    outcome = CodeInjectionCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    titles = {f.title for f in outcome.findings}
    assert any("B307" in title for title in titles)
    assert any("B102" in title for title in titles)
    assert all(f.severity == "critical" for f in outcome.findings)


def test_detects_string_built_sql_query(tmp_path: Path) -> None:
    vulnerable = tmp_path / "vulnerable.py"
    vulnerable.write_text(
        "def query_user(cursor, username: str):\n"
        '    query = "SELECT * FROM users WHERE username = \'" + username + "\'"\n'
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )

    outcome = CodeInjectionCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    matches = [f for f in outcome.findings if "B608" in f.title]
    assert matches
    assert matches[0].severity == "high"


def test_clean_source_produces_no_findings(tmp_path: Path) -> None:
    clean_file = tmp_path / "clean.py"
    clean_file.write_text(
        "import subprocess\n"
        "\n"
        "def list_dir(path: str) -> str:\n"
        "    result = subprocess.check_output(['ls', path])\n"
        "    return result.decode()\n",
        encoding="utf-8",
    )

    outcome = CodeInjectionCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    assert outcome.findings == []


def test_no_source_dir_is_skipped_not_silently_passed() -> None:
    outcome = CodeInjectionCheck().run(_DUMMY_SNAPSHOT, source_dir=None)

    assert outcome.status == "skipped"
    assert outcome.findings == []


def test_missing_source_dir_is_skipped(tmp_path: Path) -> None:
    outcome = CodeInjectionCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path / "does-not-exist")

    assert outcome.status == "skipped"
    assert outcome.findings == []


def test_non_python_source_dir_is_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "server.rb").write_text("puts 'hello'\n", encoding="utf-8")

    outcome = CodeInjectionCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "not_applicable"
    assert outcome.findings == []
    assert "Python" in (outcome.reason or "")
