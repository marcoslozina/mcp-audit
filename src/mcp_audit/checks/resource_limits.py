"""Check: rate limits / usage quotas / call budgets on tool invocations.

Without some limit on how often an agent can call a tool, a compromised or
simply overeager agent can call it without bound — a denial-of-service
against the server, or an unbounded cost against a paid third-party API the
tool wraps. This check looks for whether anything, at either the protocol
or source level, limits that.

Level 1: protocol (verified against the spec, not assumed)
------------------------------------------------------------
The MCP specification (2025-06-18) was checked directly for this, rather
than assumed. Findings:

- The `Tool` object has exactly these fields: `name`, `title`,
  `description`, `inputSchema`, `outputSchema`, `annotations`. None of them
  express a rate limit, quota, or cost budget.
- `ToolAnnotations` (the one open-ended metadata bag on a tool) has exactly
  four fields: `readOnlyHint`, `destructiveHint`, `idempotentHint`,
  `openWorldHint` — all about side-effect risk, none about usage limits.
- The `tools` server capability negotiated during `initialize` has exactly
  one field, `listChanged` — nothing about limits either.
- The spec's own "Security Considerations" for tools states servers
  **MUST** "Rate limit tool invocations" and clients **SHOULD** "Implement
  timeouts for tool calls" — so the spec *mandates* this exists, while
  providing **zero structured mechanism** for a server to declare it does,
  what the limit is, or for a client (or a scanner like mcp-audit) to
  verify compliance. That gap is the finding here, not a mistake by any
  particular server.

So: **there is no standardized protocol-level mechanism for this today.**
Same honesty rule as `TransportCheck` for stdio — reporting "passed" when
nothing could actually be verified would be dishonest, so absent
`--source-dir` this check reports NOT_APPLICABLE, not a clean pass. If the
spec ever adds one (e.g. a future `annotations` field or capability), the
speculative check below starts finding it automatically instead of
requiring a rewrite — see `_declared_limit_markers`.

Level 2: source (`--source-dir`, Python only)
------------------------------------------------
Looks for known rate-limiting library/decorator usage anywhere in each
source file (`slowapi`, `flask-limiter`/`flask_limiter`,
`django-ratelimit`, `aiolimiter`, `asyncio-throttle`, the `ratelimit`
package, `pyrate_limiter`, or a bare `@limiter`/`RateLimiter(`/`Throttle(`
pattern). If a file has none of these AND at least one MCP tool/resource
handler in it calls out to an external HTTP API or spawns a subprocess
(the two most common "unbounded cost/DoS" shapes), that handler is flagged
— **at low severity, explicitly labeled low-confidence**.

Be honest about how weak this signal is: absence of a decorator this check
recognizes is not proof of absence of rate limiting. Limiting can live in
an API gateway, a reverse proxy, the hosting platform (e.g. a serverless
concurrency cap), or a library/pattern this check's marker list doesn't
know about — none of which are visible from source alone. This check is
mostly informational value, not a confident vulnerability detector, and
says so in every finding it produces.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from mcp_audit.checks.base import Check, CheckOutcome, Finding
from mcp_audit.parser import ServerSnapshot

CHECK_ID = "resource-limits"

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache", ".pytest_cache"}

_HANDLER_DECORATOR_ATTRS = {"tool", "resource"}

# Speculative, forward-looking check for a protocol-level declaration of a
# rate limit / quota. Nothing in the current MCP spec produces any of
# these keys (see module docstring) — this is unexercised today, kept here
# so the check activates automatically instead of needing a rewrite if the
# spec ever adds such a field, mirroring TransportCheck's own "future path"
# pattern for HTTP/SSE support.
_DECLARED_LIMIT_SCHEMA_KEYS = {"x-rate-limit", "x-mcp-rate-limit", "rateLimit", "x-quota", "x-budget"}

_LIMITER_MARKERS = (
    "slowapi",
    "flask_limiter",
    "flask-limiter",
    "django_ratelimit",
    "django-ratelimit",
    "aiolimiter",
    "asyncio_throttle",
    "asyncio-throttle",
    "pyrate_limiter",
    "ratelimit",
    "@limiter",
    "RateLimiter(",
    "Throttle(",
    "TokenBucket",
)

_EXTERNAL_CALL_MARKERS: dict[str, tuple[str, ...]] = {
    "an external HTTP API": (
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
    "a subprocess/external process": (
        "subprocess.run(",
        "subprocess.check_output(",
        "subprocess.Popen(",
        "os.system(",
    ),
}

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


def _iter_python_files(source_dir: Path) -> Iterator[Path]:
    for path in sorted(source_dir.rglob("*.py")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def _declared_limit_markers(snapshot: ServerSnapshot) -> list[str]:
    """Speculative check for a schema-level rate-limit declaration.

    Always returns [] against every MCP server today (see module
    docstring) — no such field exists in the current spec. Kept as real,
    exercised code (not a stub) so a future protocol addition is picked up
    without a rewrite.
    """
    hits = []
    for tool in snapshot.tools:
        properties = (tool.input_schema or {}).get("properties", {}) or {}
        found = _DECLARED_LIMIT_SCHEMA_KEYS & (tool.input_schema or {}).keys()
        found |= _DECLARED_LIMIT_SCHEMA_KEYS & properties.keys()
        if found:
            hits.append(f"tool:{tool.name} ({', '.join(sorted(found))})")
    return hits


def _decorator_marks_handler(decorator: ast.expr) -> bool:
    node: ast.expr = decorator
    if isinstance(node, ast.Call):
        node = node.func
    return isinstance(node, ast.Attribute) and node.attr in _HANDLER_DECORATOR_ATTRS


def _is_handler(func: _FunctionNode) -> bool:
    return any(_decorator_marks_handler(dec) for dec in func.decorator_list)


def _handler_external_call_categories(source: str, func: _FunctionNode) -> list[str]:
    if not _is_handler(func):
        return []
    body_source = ast.get_source_segment(source, func) or ""
    return [category for category, markers in _EXTERNAL_CALL_MARKERS.items() if any(m in body_source for m in markers)]


def _scan_file(path: Path, source: str) -> list[Finding]:
    has_limiter = any(marker in source for marker in _LIMITER_MARKERS)
    if has_limiter:
        return []

    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError):
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        categories = _handler_external_call_categories(source, node)
        for category in categories:
            findings.append(
                Finding(
                    severity="low",
                    check_id=CHECK_ID,
                    title=f"No rate-limiting pattern found for handler '{node.name}' calling {category}",
                    description=(
                        f"Handler '{node.name}' calls {category}, and no known rate-limiting "
                        "library or decorator marker (slowapi, flask-limiter, django-ratelimit, "
                        "aiolimiter, asyncio-throttle, pyrate_limiter, ratelimit, or a bare "
                        "@limiter/RateLimiter(/Throttle() pattern) was found anywhere in this "
                        "file. Low-confidence, informational: limiting could be enforced by an "
                        "API gateway, reverse proxy, hosting platform, or a pattern this check "
                        "doesn't recognize — none of which are visible from source alone. "
                        "Absence of a recognized marker is not proof of absence of a limit."
                    ),
                    location=f"{path}:{node.lineno}",
                )
            )
    return findings


def _run_source_level(source_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_python_files(source_dir):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(_scan_file(path, source))
    return findings


class ResourceLimitsCheck(Check):
    check_id = CHECK_ID
    name = "Rate limits / usage quotas / call budgets"

    def run(self, snapshot: ServerSnapshot, source_dir: Path | None = None) -> CheckOutcome:
        declared = _declared_limit_markers(snapshot)

        if source_dir is None:
            if declared:
                return CheckOutcome(
                    check_id=self.check_id,
                    name=self.name,
                    status="ran",
                    reason=(
                        f"found a non-standard schema hint suggesting a declared limit on: "
                        f"{', '.join(declared)}. This is not a real MCP convention (see "
                        "module docstring) — treat it as informational only."
                    ),
                    findings=[],
                )
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="not_applicable",
                reason=(
                    "the MCP specification (2025-06-18) has no standardized mechanism for a "
                    "server to declare a rate limit, usage quota, or cost budget on a tool — "
                    "verified directly against the spec's Tool/ToolAnnotations/tools-capability "
                    "fields, not assumed. The spec's own security considerations say servers "
                    "MUST rate limit tool invocations, but gives no structured way to declare "
                    "or verify that they do. This is a structural gap in the MCP ecosystem "
                    "today, not a defect in this specific server — this check will activate "
                    "fully if/when the spec adds such a field. Re-run with --source-dir to run "
                    "a (heuristic, low-confidence) check for rate-limiting patterns in the "
                    "server's actual source instead."
                ),
                findings=[],
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
                    f"no Python source files (*.py) found under {source_dir}. This check's "
                    "source-level heuristic looks for Python rate-limiting libraries/decorators "
                    "and has no equivalent today for other languages — combined with no "
                    "standardized protocol-level mechanism either (see this check's module "
                    "docstring), nothing could be evaluated for this scan."
                ),
                findings=[],
            )

        findings = _run_source_level(source_dir)
        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            reason=(
                "no standardized protocol-level rate-limit declaration exists (see module "
                f"docstring); scanned {len(python_files)} Python source file(s) under "
                f"{source_dir} for known rate-limiting library/decorator usage instead. "
                "Low-confidence heuristic — see finding descriptions."
            ),
            findings=findings,
        )
