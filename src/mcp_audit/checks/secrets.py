"""Check: hardcoded secrets in the target server's source code.

This check is fundamentally different from the others in this package: it
does not (and cannot) inspect the MCP protocol surface, because a secret
sitting in `config.py` next to a tool definition is invisible to
`tools/list` — the server would have to be careless enough to leak it back
through the protocol for a runtime-only check to see it. So this check
requires the operator to point mcp-audit at the server's source directory
via `--source-dir`; if they don't, we report the check as explicitly
SKIPPED rather than silently passing.

Detection strategy (conceptually inspired by the public rule sets of
tools like detect-secrets and gitleaks — no code copied, only the general
categories of regex heuristics, which are common industry knowledge):

  1. High-confidence vendor key formats (AWS access keys, OpenAI-style
     `sk-...` keys, Google API keys, GitHub tokens, Slack tokens, private
     key PEM headers) -> "critical".
  2. Assignment patterns that name a secret-like variable
     (`api_key = "..."`, `password: "..."`) -> "high".
  3. Generic high-entropy string literals that don't match anything above
     -> "medium" (higher false-positive rate, flagged for human review).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.checks.base import Check, CheckOutcome, Finding
from mcp_audit.parser import ServerSnapshot

CHECK_ID = "secrets-hardcoded"

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache", ".pytest_cache"}
_SCAN_SUFFIXES = {
    ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env", ".txt",
}


@dataclass(frozen=True)
class _VendorPattern:
    name: str
    regex: re.Pattern[str]
    severity: str = "critical"


_VENDOR_PATTERNS: list[_VendorPattern] = [
    _VendorPattern("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    _VendorPattern("AWS secret-looking assignment", re.compile(
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"][A-Za-z0-9/+=]{30,}['\"]"
    )),
    _VendorPattern("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    _VendorPattern("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    _VendorPattern("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    _VendorPattern("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    _VendorPattern("Private key block", re.compile(
        r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"
    )),
]

# variable = "value" / variable: "value", where the variable name looks
# secret-like and the value is a plausible literal (not a placeholder).
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|"
    r"token|passwd|password|client[_-]?secret)\b\s*[:=]\s*['\"]([^'\"]{6,})['\"]"
)

_PLACEHOLDER_RE = re.compile(
    r"(?i)^(changeme|change[_-]?me|your[_-].*|xxx+|todo|example|placeholder|"
    r"<.*>|\$\{.*\}|test|dummy|fake|none|null)$"
)

_QUOTED_STRING_RE = re.compile(r"""['"]([A-Za-z0-9_\-+/=]{20,})['"]""")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match(value.strip()))


def _iter_source_files(source_dir: Path):
    for path in sorted(source_dir.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in _SCAN_SUFFIXES:
            continue
        yield path


class SecretsCheck(Check):
    check_id = CHECK_ID
    name = "Hardcoded secrets in source"

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

        findings: list[Finding] = []
        matched_spans: set[tuple[Path, int, int]] = set()

        for path in _iter_source_files(source_dir):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for pattern in _VENDOR_PATTERNS:
                for match in pattern.regex.finditer(text):
                    line_no = text.count("\n", 0, match.start()) + 1
                    matched_spans.add((path, match.start(), match.end()))
                    findings.append(
                        Finding(
                            severity=pattern.severity,
                            check_id=self.check_id,
                            title=f"Hardcoded {pattern.name}",
                            description=(
                                f"Matched vendor secret pattern '{pattern.name}' in source code."
                            ),
                            location=f"{path}:{line_no}",
                        )
                    )

            for match in _ASSIGNMENT_PATTERN.finditer(text):
                var_name, value = match.group(1), match.group(2)
                if _is_placeholder(value):
                    continue
                if (path, match.start(), match.end()) in matched_spans:
                    continue
                line_no = text.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        severity="high",
                        check_id=self.check_id,
                        title=f"Hardcoded secret-like assignment ({var_name})",
                        description=(
                            f"Variable '{var_name}' is assigned a literal string that looks "
                            "like a credential rather than a placeholder."
                        ),
                        location=f"{path}:{line_no}",
                    )
                )
                matched_spans.add((path, match.start(), match.end()))

            for match in _QUOTED_STRING_RE.finditer(text):
                if (path, match.start(), match.end()) in matched_spans:
                    continue
                value = match.group(1)
                if _is_placeholder(value):
                    continue
                entropy = _shannon_entropy(value)
                # Threshold picked to flag base64/hex-like blobs while
                # leaving ordinary prose and identifiers alone.
                if entropy >= 4.0:
                    line_no = text.count("\n", 0, match.start()) + 1
                    findings.append(
                        Finding(
                            severity="medium",
                            check_id=self.check_id,
                            title="High-entropy string literal",
                            description=(
                                f"String literal has Shannon entropy {entropy:.2f} bits/char "
                                f"(len={len(value)}), which is typical of API keys/tokens but "
                                "can also be a false positive (hashes, IDs, etc). Review manually."
                            ),
                            location=f"{path}:{line_no}",
                        )
                    )

        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            findings=findings,
        )
