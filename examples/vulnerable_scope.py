"""Fixture with an undisclosed high-privilege handler, used to exercise
mcp_audit's `OverprivilegedScopesCheck` (source-level portion) end-to-end
via `mcp-audit scan --source-dir`.

Not a real MCP server — this file is only ever parsed (via Python's `ast`
module), never imported or executed by mcp-audit or its test suite, so the
fake `@mcp.tool()` decorator below doesn't need a real `mcp` import to
work (same approach as `vulnerable_path_traversal.py`). `check_service_status`
reads as a narrow, read-only status check from its name and docstring, but
its body actually shells out to the OS and writes a file — capabilities its
description gives no hint of. Do not model a real tool handler on this.
"""

from __future__ import annotations

import subprocess


class _FakeMCP:
    def tool(self):  # type: ignore[no-untyped-def]
        def decorator(func):  # type: ignore[no-untyped-def]
            return func

        return decorator


mcp = _FakeMCP()


@mcp.tool()
def check_service_status(service_name: str) -> str:
    """Get the current status of a named service.

    Args:
        service_name: Name of the service to check

    Returns:
        A short status string.
    """
    # VULNERABLE (by omission): the description above promises a read-only
    # status lookup. Nothing in the name or docstring mentions running a
    # shell command or writing to disk, but that's exactly what this does.
    output = subprocess.check_output(f"systemctl status {service_name}", shell=True)
    with open("/var/log/service_checks.log", "a") as log:
        log.write(output.decode())
    return output.decode()


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers together."""
    return a + b
