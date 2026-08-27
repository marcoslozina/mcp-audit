"""Check: code / command injection patterns in the target server's Python source.

Like `SecretsCheck`, this cannot work from the MCP protocol surface alone —
`tools/list` tells you a tool's name and schema, not how its handler builds
a shell command or a SQL query internally. So this check also requires
`--source-dir`; without it, we report the check as explicitly SKIPPED
rather than silently passing.

Implementation choice: bandit, not hand-rolled regex
-----------------------------------------------------
This is the class of bug behind real MCP CVEs (including in the official
Git MCP server) and behind the "all reference servers scored an F" audit
cited in this project's README — subprocess calls built from unsanitized
input, `os.system`, `eval`/`exec`, and string-built SQL queries. These are
exactly the patterns Python's standard security linter, `bandit`
(https://github.com/PyCQA/bandit), was built to detect, with rules that
have been tuned against years of real-world false positives — writing a
parallel set of regexes for "subprocess call with shell=True and a
non-constant argument" would either under-detect (miss `Popen`, miss
keyword-argument `shell=True`, miss values built through an intermediate
variable) or reimplement, badly, logic bandit already gets right via a
real AST visitor. So this check calls bandit's Python API directly
(`bandit.core.manager.BanditManager`) and maps a deliberately narrow
allowlist of its ~70 checks onto `mcp-audit`'s `Finding` model — bandit
covers far more ground (weak crypto, insecure temp files, YAML loading,
etc.) than "code/command injection", and surfacing all of it here would
misrepresent what this specific check claims to do.

(By contrast, `PathTraversalCheck` in this package does NOT use bandit —
bandit has no dedicated path-traversal rule, because "does this value
that reaches `open()` stay inside an allowed directory" requires
understanding which function parameters are attacker-controlled MCP tool
input, not just generic taint analysis. That's purpose-built AST logic
instead; see `path_traversal.py` for why.)

Scope: Python only, today. Bandit only understands Python; if
`--source-dir` doesn't contain any `.py` files, this check has nothing to
analyze and reports NOT APPLICABLE (not "no findings" — those mean
different things, see `checks/base.py`).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from bandit.core import config as bandit_config
from bandit.core import manager as bandit_manager

from mcp_audit.checks.base import Check, CheckOutcome, Finding, Severity
from mcp_audit.parser import ServerSnapshot

CHECK_ID = "code-injection"

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache", ".pytest_cache"}

# Deliberate allowlist of bandit test IDs that map onto "code/command
# injection" specifically (bandit's full rule set is much broader — weak
# crypto, insecure temp files, assert usage, etc. — and reporting all of
# it under a check named "code-injection" would be dishonest about scope).
#
#   B102 - exec() used
#   B307 - eval() used
#   B602 - subprocess call with shell=True
#   B604 - some other function called with shell=True
#   B605 - os.system() / starting a process via a shell
#   B608 - SQL query built via string concatenation/formatting
#
# Severity: the first five are direct arbitrary code/command execution if
# the interpolated value is attacker-controlled -> "critical", matching how
# this project treats the vendor-key matches in SecretsCheck. B608 (SQL
# built as a string) is "high" — serious, but the SQL driver still mediates
# execution rather than handing the interpreter a raw shell.
_RELEVANT_BANDIT_TESTS: dict[str, tuple[str, Severity]] = {
    "B102": ("Use of exec()", "critical"),
    "B307": ("Use of eval()", "critical"),
    "B602": ("subprocess call with shell=True", "critical"),
    "B604": ("function call with shell=True", "critical"),
    "B605": ("process started via a shell (e.g. os.system)", "critical"),
    "B608": ("SQL query built via string concatenation/formatting", "high"),
}


def _iter_python_files(source_dir: Path) -> Iterator[Path]:
    for path in sorted(source_dir.rglob("*.py")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


class CodeInjectionCheck(Check):
    check_id = CHECK_ID
    name = "Code / command injection in source"

    def run(self, snapshot: ServerSnapshot, source_dir: Path | None = None) -> CheckOutcome:
        if source_dir is None:
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="skipped",
                reason=(
                    "no --source-dir provided; mcp-audit cannot inspect the target "
                    "server's source code from the MCP protocol alone, so this "
                    "check was not run. Re-run with --source-dir <path> to enable it."
                ),
            )

        source_dir = Path(source_dir)
        if not source_dir.exists():
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="skipped",
                reason=f"--source-dir {source_dir} does not exist.",
            )

        python_files = list(_iter_python_files(source_dir))
        if not python_files:
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="not_applicable",
                reason=(
                    f"no Python source files (*.py) found under {source_dir}. This "
                    "check wraps bandit, a Python-specific static analyzer, and has "
                    "no equivalent today for servers written in other languages — "
                    "this is not the same as 'passed', nothing was analyzed."
                ),
            )

        b_conf = bandit_config.BanditConfig()
        manager = bandit_manager.BanditManager(b_conf, "file", quiet=True)
        manager.discover_files([str(path) for path in python_files], recursive=False)
        manager.run_tests()

        findings: list[Finding] = []
        for issue in manager.get_issue_list():
            mapped = _RELEVANT_BANDIT_TESTS.get(issue.test_id)
            if mapped is None:
                continue
            label, severity = mapped
            findings.append(
                Finding(
                    severity=severity,
                    check_id=self.check_id,
                    title=f"{label} ({issue.test_id})",
                    description=(f"{issue.text.strip()} [bandit {issue.test_id}, confidence {issue.confidence}]"),
                    # bandit normalizes relative paths to "./foo" internally
                    # (see BanditManager.discover_files); route through Path
                    # to collapse that back to the plain form the rest of
                    # mcp-audit's locations use (see e.g. SecretsCheck).
                    location=f"{Path(issue.fname)}:{issue.lineno}",
                )
            )

        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            findings=findings,
        )
