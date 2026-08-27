"""Fixture with a command-injection pattern, used to exercise mcp_audit's
`CodeInjectionCheck` (bandit-backed) end-to-end via
`mcp-audit scan --source-dir`.

Not a real MCP server, not something to run — purely a static fixture.
The shape mirrors Damn Vulnerable MCP Server's "Challenge 9 - Remote
Access Control" (`ping_host`) and the class of bug behind real MCP CVEs:
an f-string builds a shell command straight from a tool parameter and runs
it with `shell=True`. Do not model a real tool handler on this.
"""

from __future__ import annotations

import subprocess


def ping_host(host: str, count: int = 4) -> str:
    """VULNERABLE: `host` reaches a shell command via an f-string, then
    `subprocess.check_output(..., shell=True)` executes it — a semicolon
    or `&&` in `host` runs arbitrary commands.
    """
    command = f"ping -c {count} {host}"
    result = subprocess.check_output(command, shell=True)
    return result.decode()
