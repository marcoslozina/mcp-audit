"""Check: a tool declares or uses broader access than its name/description implies.

This is the "excessive permission scope" attack class — the tool's own
metadata (or, with `--source-dir`, its actual handler code) grants more
capability than a human approving it would reasonably expect from what
it says it does. Damn Vulnerable MCP Server's "Challenge 3 - Excessive
Permission Scope" is the canonical example: a `read_file` tool described
as reading "a file from the public directory" that actually accepts any
path with no server-side restriction.

Two independent levels, both heuristic
----------------------------------------
1. Protocol level (always runs, no `--source-dir` needed): looks only at
   `tool.description` and `tool.input_schema`, the only things `tools/list`
   exposes.
     a. "Scope-narrowing description, unconstrained parameter": the
        description uses language that promises a restricted/bounded
        operation (e.g. "public", "only", "restricted", "within the ...
        directory"), but the schema hands that promise no protocol-level
        teeth — a parameter that looks like a resource locator (file,
        path, dir, ...) is a bare `string` with no `enum`/`pattern`/
        `const` narrowing what it can hold. Enforcement, if it exists at
        all, is entirely inside code this level can't see.
     b. "Undisclosed multi-category parameters": the schema's parameter
        names span multiple privilege categories (filesystem, network,
        process execution, write/mutation) that the description text
        doesn't mention. Weaker signal than (a) — parameter *names* are a
        convention, not a capability declaration.

   Be honest about what this is: naming and schema shape are conventions,
   not enforcement. A tool can look narrow and still be narrow in practice
   (the description was accurate and the server enforces it in code this
   check can't see), or look broad here and still be safe. Every finding
   from this level says exactly that in its description.

2. Source level (`--source-dir`, Python only): parses each MCP tool/
   resource handler's AST and checks whether it imports/calls a
   high-privilege primitive (`subprocess`, `os.system`/`os.popen`, raw
   `socket`, an HTTP client hitting an arbitrary/parameterized host,
   filesystem writes/deletes) that neither the handler's name nor its
   docstring mentions. Stronger evidence than the protocol-level checks
   (this is real code, not just naming), but still just a keyword-overlap
   heuristic on free-text description vs. a fixed marker list — a
   handler can legitimately do exactly what it says using different
   words than the ones this check looks for, which reads as a false
   positive. Treat every finding here as "worth a human look", not a
   confirmed vulnerability, same posture as `path_traversal.py`.

Scope: the protocol level works for any MCP server MCP-audit can connect
to. The source level is Python-only, same reason as `CodeInjectionCheck`
and `PathTraversalCheck` — it parses Python's own AST.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from mcp_audit.checks.base import Check, CheckOutcome, Finding
from mcp_audit.parser import ServerSnapshot, ToolInfo

CHECK_ID = "overprivileged-scopes"

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache", ".pytest_cache"}

# --- Protocol-level heuristic (a): scope-narrowing description ------------

# Phrases that read as the author promising a bounded/restricted operation.
# Deliberately conservative (specific multi-word phrases, not single common
# words) to keep this from firing on ordinary descriptions like toy_server's
# "Add two numbers together." — see tests for the false-positive check.
_NARROW_SCOPE_MARKERS = (
    "public director",
    "only the",
    "only within",
    "restricted to",
    "within the",
    "read-only",
    "allowed director",
    "sandbox",
    "limited to",
    "a single ",
    "the specified director",
)

# Parameter names that look like they locate a filesystem resource. A bare
# string here, with no enum/pattern/const, is exactly the shape of DVMCP
# Challenge 3's `read_file(filename: str)`.
_RESOURCE_LOCATOR_PARAM_NAMES = {"file", "filename", "path", "filepath", "pathname", "dir", "directory", "folder"}

# Schema keys that would meaningfully constrain a string value beyond "any
# string". Their absence is what makes a resource-locator parameter "wide
# open" for this heuristic's purposes.
_CONSTRAINING_SCHEMA_KEYS = {"enum", "pattern", "const"}

# --- Protocol-level heuristic (b): undisclosed multi-category params ------

_CATEGORY_PARAM_MARKERS: dict[str, tuple[str, ...]] = {
    "filesystem": ("file", "filename", "path", "dir", "directory", "folder"),
    "write/mutation": ("content", "body", "payload", "data"),
    "network": ("url", "host", "endpoint", "uri", "hostname"),
    "process execution": ("command", "cmd", "script"),
}

_CATEGORY_DISCLOSURE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "filesystem": ("file", "path", "director", "read", "write", "save"),
    "write/mutation": ("write", "save", "update", "modify", "create", "store", "upload"),
    "network": ("http", "network", "request", "fetch", "download", "upload", "url", "api", "web", "remote"),
    "process execution": ("run", "execute", "command", "shell", "script", "invoke", "process"),
}

# --- Source-level heuristic ------------------------------------------------

_HANDLER_DECORATOR_ATTRS = {"tool", "resource"}

_SOURCE_CATEGORY_MARKERS: dict[str, tuple[str, ...]] = {
    "process execution (subprocess/os.system)": ("subprocess.", "os.system(", "os.popen(", "os.spawnl", "os.spawnv"),
    "raw network sockets": ("socket.socket(", "socket.create_connection("),
    "arbitrary HTTP requests": (
        "requests.get(",
        "requests.post(",
        "requests.put(",
        "requests.delete(",
        "requests.request(",
        "httpx.get(",
        "httpx.post(",
        "httpx.Client(",
        "httpx.AsyncClient(",
        "urllib.request.urlopen(",
        "aiohttp.ClientSession(",
    ),
    "filesystem writes/deletes": (
        '"w")',
        "'w')",
        '"a")',
        "'a')",
        '"wb")',
        "'wb')",
        "os.remove(",
        "os.unlink(",
        "shutil.rmtree(",
        "shutil.move(",
    ),
}

_SOURCE_CATEGORY_DISCLOSURE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "process execution (subprocess/os.system)": (
        "run",
        "execute",
        "command",
        "shell",
        "script",
        "invoke",
        "process",
        "spawn",
    ),
    "raw network sockets": ("socket", "network", "connection", "port"),
    "arbitrary HTTP requests": (
        "http",
        "request",
        "fetch",
        "download",
        "upload",
        "url",
        "api",
        "web",
        "network",
        "remote",
        "endpoint",
    ),
    "filesystem writes/deletes": ("write", "save", "delete", "remove", "modify", "update", "create", "store"),
}

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def _iter_python_files(source_dir: Path) -> Iterator[Path]:
    for path in sorted(source_dir.rglob("*.py")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


# --- Protocol-level analysis ------------------------------------------------


def _property_is_unconstrained_string(prop_schema: dict[str, Any]) -> bool:
    prop_type = prop_schema.get("type")
    if prop_type not in (None, "string"):
        return False
    return not (_CONSTRAINING_SCHEMA_KEYS & prop_schema.keys())


def _check_scope_narrowing(tool: ToolInfo) -> list[Finding]:
    description = (tool.description or "").lower()
    if not any(marker in description for marker in _NARROW_SCOPE_MARKERS):
        return []

    properties = (tool.input_schema or {}).get("properties", {}) or {}
    findings: list[Finding] = []
    for param_name, prop_schema in properties.items():
        if param_name.lower() not in _RESOURCE_LOCATOR_PARAM_NAMES:
            continue
        if not isinstance(prop_schema, dict) or not _property_is_unconstrained_string(prop_schema):
            continue
        findings.append(
            Finding(
                severity="medium",
                check_id=CHECK_ID,
                title=f"Tool '{tool.name}' promises a restricted scope its schema doesn't enforce",
                description=(
                    f"Tool '{tool.name}'s description ('{tool.description}') reads as promising "
                    f"a bounded/restricted operation, but its '{param_name}' parameter is a plain "
                    "string with no enum/pattern/const narrowing what value it can hold — nothing "
                    "at the protocol level stops a caller from passing an arbitrary value (e.g. "
                    "'../../etc/passwd'). This is a naming/schema heuristic, not proof of a "
                    "vulnerability: the server may enforce the restriction in code this check "
                    "can't see without --source-dir. Re-run with --source-dir to check the actual "
                    "handler."
                ),
                location=f"tool:{tool.name}",
            )
        )
    return findings


def _check_undisclosed_categories(tool: ToolInfo) -> list[Finding]:
    description = (tool.name + " " + (tool.description or "")).lower()
    properties = (tool.input_schema or {}).get("properties", {}) or {}
    param_names = {name.lower() for name in properties}

    categories_present = {
        category
        for category, markers in _CATEGORY_PARAM_MARKERS.items()
        if any(marker in param_name for param_name in param_names for marker in markers)
    }
    if len(categories_present) < 2:
        return []

    disclosed = {
        category
        for category in categories_present
        if any(kw in description for kw in _CATEGORY_DISCLOSURE_KEYWORDS[category])
    }
    undisclosed = categories_present - disclosed
    if not undisclosed:
        return []

    return [
        Finding(
            severity="low",
            check_id=CHECK_ID,
            title=f"Tool '{tool.name}' combines multiple privilege categories in its parameters",
            description=(
                f"Tool '{tool.name}'s parameters span {sorted(categories_present)} "
                f"(by parameter-name convention), but its name/description doesn't clearly "
                f"reflect {sorted(undisclosed)}. Weak signal: parameter names are a naming "
                "convention, not a capability declaration — worth a human glance, not a "
                "confirmed finding."
            ),
            location=f"tool:{tool.name}",
        )
    ]


def _run_protocol_level(snapshot: ServerSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for tool in snapshot.tools:
        findings.extend(_check_scope_narrowing(tool))
        findings.extend(_check_undisclosed_categories(tool))
    return findings


# --- Source-level analysis --------------------------------------------------


def _decorator_marks_handler(decorator: ast.expr) -> bool:
    node: ast.expr = decorator
    if isinstance(node, ast.Call):
        node = node.func
    return isinstance(node, ast.Attribute) and node.attr in _HANDLER_DECORATOR_ATTRS


def _is_handler(func: _FunctionNode) -> bool:
    return any(_decorator_marks_handler(dec) for dec in func.decorator_list)


def _find_findings_in_function(path: Path, source: str, func: _FunctionNode) -> list[Finding]:
    if not _is_handler(func):
        return []

    body_source = ast.get_source_segment(source, func) or ""
    disclosure_text = f"{func.name} {ast.get_docstring(func) or ''}".lower()

    findings: list[Finding] = []
    for category, markers in _SOURCE_CATEGORY_MARKERS.items():
        if not any(marker in body_source for marker in markers):
            continue
        keywords = _SOURCE_CATEGORY_DISCLOSURE_KEYWORDS[category]
        if any(kw in disclosure_text for kw in keywords):
            continue
        findings.append(
            Finding(
                severity="medium",
                check_id=CHECK_ID,
                title=f"Handler '{func.name}' uses {category} not reflected in its name/description",
                description=(
                    f"Handler '{func.name}' contains code matching {category}, but neither its "
                    "function name nor its docstring/description mentions anything related. A "
                    "human approving this tool from its listed description alone would not "
                    "expect this capability. Heuristic keyword-overlap check: the handler may "
                    "legitimately do this using different wording than this check looks for — "
                    "treat this as worth a human look, not a confirmed vulnerability."
                ),
                location=f"{path}:{func.lineno}",
            )
        )
    return findings


def _run_source_level(source_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_python_files(source_dir):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                findings.extend(_find_findings_in_function(path, source, node))
    return findings


class OverprivilegedScopesCheck(Check):
    check_id = CHECK_ID
    name = "Overprivileged tool scopes"

    def run(self, snapshot: ServerSnapshot, source_dir: Path | None = None) -> CheckOutcome:
        findings = _run_protocol_level(snapshot)

        if source_dir is None:
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="ran",
                reason=(
                    "protocol-level only: compared each tool's description/input_schema for a "
                    "scope-vs-schema mismatch. Re-run with --source-dir to also check the "
                    "server's actual handler code for undisclosed high-privilege calls "
                    "(subprocess, sockets, arbitrary HTTP, filesystem writes)."
                ),
                findings=findings,
            )

        source_dir = Path(source_dir)
        if not source_dir.exists():
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="ran",
                reason=(
                    f"protocol-level analysis ran; the source-level portion did not because "
                    f"--source-dir {source_dir} does not exist."
                ),
                findings=findings,
            )

        python_files = list(_iter_python_files(source_dir))
        if not python_files:
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="ran",
                reason=(
                    "protocol-level analysis ran; the source-level portion did not because no "
                    f"Python source files (*.py) were found under {source_dir} — this check's "
                    "source-level heuristic parses Python's own AST and has no equivalent today "
                    "for other languages."
                ),
                findings=findings,
            )

        findings.extend(_run_source_level(source_dir))
        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            reason="protocol-level and source-level analysis both ran.",
            findings=findings,
        )
