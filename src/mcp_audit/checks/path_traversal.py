"""Check: path traversal via unsanitized input in an MCP tool/resource handler.

Same access requirement as `SecretsCheck` and `CodeInjectionCheck`: this
inspects source code on disk, not the MCP protocol surface, so it needs
`--source-dir` and reports SKIPPED without it.

Why this isn't bandit-based (unlike `CodeInjectionCheck`)
-----------------------------------------------------------
bandit has no dedicated "path traversal" rule. Deciding whether a value
that reaches `open()` is dangerous requires knowing *where the value came
from* — specifically, whether it originates from a parameter of a function
that an MCP client can actually invoke (a `@mcp.tool()` / `@server.tool()`
/ `@mcp.resource()` handler). That's a narrower, MCP-specific question than
generic taint analysis, so this check is purpose-built: it parses each
source file's AST, finds functions decorated as an MCP tool/resource
handler, and flags any handler where a parameter (or a simple local
variable built from one, e.g. `path = os.path.join(base, name)`) reaches
`open()` / `<expr>.open()` with no sanitization call
(`os.path.realpath`, `Path.resolve`, `os.path.commonpath`,
`Path.is_relative_to`, `secure_filename`, or similar) anywhere in the same
function.

Known limitations (documented deliberately, not swept under the rug):

- This is a heuristic, intraprocedural, single-pass AST check — not real
  dataflow/taint analysis. It has no loop fixpoint, no branch-sensitivity,
  and no cross-function tracking: if a handler forwards its parameter to a
  helper function defined elsewhere and *that* function is where the
  unsanitized `open()` call lives, this check will not connect the two.
- It can false-positive: a handler might sanitize input in a way this
  check doesn't recognize (e.g. a custom allowlist check instead of
  `realpath`/`resolve`), or the "base directory" join might already be
  safe for reasons not visible in the function body alone.
- It can false-negative: sanitization performed in a decorator, a
  middleware layer, or before the value ever reaches the handler (e.g. by
  the MCP framework itself) is invisible to a per-function AST check.

A scanner that hid these limitations to look more precise would be
violating the same "report what we didn't check" principle this whole
project is built around — see `checks/base.py`'s `CheckOutcome.status`
docstring. Treat every finding from this check as "worth a human look",
not as a confirmed vulnerability.

Scope: Python only, today, for the same reason as `CodeInjectionCheck` —
this check parses Python's own AST, which has no equivalent for other
languages. No `.py` files under `--source-dir` -> NOT APPLICABLE, not
"passed".
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from mcp_audit.checks.base import Check, CheckOutcome, Finding
from mcp_audit.parser import ServerSnapshot

CHECK_ID = "path-traversal"

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache", ".pytest_cache"}

# Decorator attribute names that mark a function as reachable from an MCP
# client. `@mcp.prompt()` is deliberately excluded — prompt handlers return
# templated text, not file contents, so they're a poor fit for this
# specific attack class.
_HANDLER_DECORATOR_ATTRS = {"tool", "resource"}

# Sink call shapes: a bare `open(...)` call, or `<expr>.open(...)` (e.g.
# `pathlib.Path(user_input).open()`).
_SINK_CALL_NAMES = {"open"}

# Substrings that, if present anywhere in a handler's own source text,
# count as "visible sanitization" for that handler. Deliberately
# string-based rather than another AST pattern: simple, auditable, and
# permissive enough to avoid flagging code that's clearly trying to guard
# against traversal even if this check can't verify the guard is correct.
_SANITIZATION_MARKERS = (
    "resolve(",
    "realpath(",
    "commonpath(",
    "is_relative_to(",
    "secure_filename(",
)

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def _iter_python_files(source_dir: Path) -> Iterator[Path]:
    for path in sorted(source_dir.rglob("*.py")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def _decorator_marks_handler(decorator: ast.expr) -> bool:
    node: ast.expr = decorator
    if isinstance(node, ast.Call):
        node = node.func
    return isinstance(node, ast.Attribute) and node.attr in _HANDLER_DECORATOR_ATTRS


def _is_handler(func: _FunctionNode) -> bool:
    return any(_decorator_marks_handler(dec) for dec in func.decorator_list)


def _param_names(func: _FunctionNode) -> set[str]:
    args = func.args
    names = {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
    names -= {"self", "cls"}
    return names


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _iter_statements(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Flatten a function body into one source-order stream of statements.

    Descends into if/for/while/try/with blocks (and except handlers) so a
    simple linear taint pass can walk straight-line-shaped code as a single
    sequence. This is NOT real control-flow analysis — branches are just
    concatenated in the order they appear in source, and loop bodies are
    visited once, not iterated to a fixpoint. It's enough to follow the
    extremely common `path = os.path.join(base, name); open(path)` shape
    without a real dataflow engine.
    """
    for stmt in body:
        yield stmt
        for attr in ("body", "orelse", "finalbody"):
            nested = getattr(stmt, attr, None)
            if nested:
                yield from _iter_statements(nested)
        for handler in getattr(stmt, "handlers", None) or []:
            yield from _iter_statements(handler.body)


def _is_sink_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in _SINK_CALL_NAMES
    if isinstance(func, ast.Attribute):
        return func.attr in _SINK_CALL_NAMES
    return False


def _is_sanitized(source: str, func: _FunctionNode) -> bool:
    segment = ast.get_source_segment(source, func) or ""
    return any(marker in segment for marker in _SANITIZATION_MARKERS)


def _find_findings_in_function(path: Path, source: str, func: _FunctionNode) -> list[Finding]:
    if not _is_handler(func):
        return []

    tainted = _param_names(func)
    if not tainted or _is_sanitized(source, func):
        return []

    findings: list[Finding] = []
    seen_calls: set[tuple[int, int]] = set()

    for stmt in _iter_statements(func.body):
        # Propagate taint through simple `name = <expr>` assignments, so a
        # value built FROM a parameter (not just the parameter itself)
        # reaching a sink is still recognized.
        if isinstance(stmt, ast.Assign) and _names_in(stmt.value) & tainted:
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    tainted.add(target.id)
        elif (
            isinstance(stmt, ast.AnnAssign)
            and stmt.value is not None
            and isinstance(stmt.target, ast.Name)
            and _names_in(stmt.value) & tainted
        ):
            tainted.add(stmt.target.id)

        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call) or not _is_sink_call(node):
                continue
            call_args = [*node.args, *(kw.value for kw in node.keywords)]
            tainted_args = {name for arg in call_args for name in _names_in(arg)} & tainted
            if not tainted_args:
                continue
            key = (node.lineno, node.col_offset)
            if key in seen_calls:
                continue
            seen_calls.add(key)
            findings.append(
                Finding(
                    severity="high",
                    check_id=CHECK_ID,
                    title=f"Potential path traversal in handler '{func.name}'",
                    description=(
                        f"Handler '{func.name}' passes parameter(s) {sorted(tainted_args)} "
                        "into a file-open call with no visible sanitization "
                        "(no os.path.realpath/Path.resolve + prefix check, or similar, "
                        "found in this function). A caller could supply a value like "
                        "'../../etc/passwd' to read or write outside the intended "
                        "directory. Heuristic AST check with known false positives/"
                        "negatives — see README's 'Checks implemented' table and "
                        "path_traversal.py's module docstring for its limitations."
                    ),
                    location=f"{path}:{node.lineno}",
                )
            )

    return findings


class PathTraversalCheck(Check):
    check_id = CHECK_ID
    name = "Path traversal via unsanitized handler input"

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
                    "check parses Python's own AST and has no equivalent today for "
                    "servers written in other languages — this is not the same as "
                    "'passed', nothing was analyzed."
                ),
            )

        findings: list[Finding] = []
        for path in python_files:
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source, filename=str(path))
            except (OSError, SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    findings.extend(_find_findings_in_function(path, source, node))

        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            findings=findings,
        )
