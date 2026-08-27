"""Tests for SecretsCheck.

SecretsCheck inspects source code on disk (via --source-dir), not the MCP
protocol surface, so the ServerSnapshot passed to `run()` is irrelevant to
its logic — a minimal placeholder is enough.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.secrets import SecretsCheck
from mcp_audit.parser import ServerSnapshot

REPO_ROOT = Path(__file__).parent.parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"

_DUMMY_SNAPSHOT = ServerSnapshot(server_name="dummy", server_version=None, protocol_version=None)


def test_detects_hardcoded_secret_in_vulnerable_config() -> None:
    outcome = SecretsCheck().run(_DUMMY_SNAPSHOT, source_dir=EXAMPLES_DIR)

    assert outcome.status == "ran"
    matches = [f for f in outcome.findings if "vulnerable_config.py" in f.location]
    assert matches, "expected at least one finding in examples/vulnerable_config.py"

    openai_key_findings = [f for f in matches if "OpenAI-style API key" in f.title]
    assert len(openai_key_findings) == 1
    assert openai_key_findings[0].severity == "critical"


def test_clean_source_produces_no_findings(tmp_path: Path) -> None:
    clean_file = tmp_path / "clean_config.py"
    clean_file.write_text(
        'APP_NAME = "mcp-audit"\nDEBUG = False\nMAX_RETRIES = 3\n',
        encoding="utf-8",
    )

    outcome = SecretsCheck().run(_DUMMY_SNAPSHOT, source_dir=tmp_path)

    assert outcome.status == "ran"
    assert outcome.findings == []


def test_no_source_dir_is_skipped_not_silently_passed() -> None:
    outcome = SecretsCheck().run(_DUMMY_SNAPSHOT, source_dir=None)

    assert outcome.status == "skipped"
    assert outcome.findings == []
