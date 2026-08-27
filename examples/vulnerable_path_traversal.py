"""Fixture with a path-traversal pattern, used to exercise mcp_audit's
`PathTraversalCheck` end-to-end via `mcp-audit scan --source-dir`.

Not a real MCP server — this file is only ever parsed (via Python's `ast`
module), never imported or executed by mcp-audit or its test suite, so the
fake `@mcp.tool()` decorator below doesn't need a real `mcp` import to
work. The shape mirrors Damn Vulnerable MCP Server's "Challenge 3 -
Excessive Permission Scope" (`read_file`): a tool parameter reaches
`open()` through a joined path with no realpath/prefix check. Do not model
a real tool handler on this.
"""

from __future__ import annotations

import os


class _FakeMCP:
    def tool(self):  # type: ignore[no-untyped-def]
        def decorator(func):  # type: ignore[no-untyped-def]
            return func

        return decorator


mcp = _FakeMCP()


@mcp.tool()
def read_report(filename: str) -> str:
    """VULNERABLE: `filename` reaches `open()` via `os.path.join` with no
    `os.path.realpath`/`Path.resolve` + prefix check, so a caller can pass
    '../../etc/passwd' to escape the intended reports directory.
    """
    path = os.path.join("/srv/reports", filename)
    with open(path, encoding="utf-8") as handle:
        return handle.read()
