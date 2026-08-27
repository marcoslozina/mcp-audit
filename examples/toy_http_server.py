"""HTTP (Streamable HTTP) variant of toy_server.py, used to exercise
mcp-audit's remote-transport support end-to-end.

Imports the exact same `MCPServer` app object as toy_server.py — same three
tools, one resource, one prompt, unmodified — and serves it over Streamable
HTTP (the remote transport defined by the MCP spec, 2025-06-18) instead of
stdio. No authentication is configured, on purpose: this is also the
fixture `unauthenticated-discovery` is exercised against (see
tests/checks/test_unauthenticated_discovery.py and
tests/test_parser_http.py), since it hands out its full tool list to
anyone who reaches the URL with zero headers.

Run standalone:
    python examples/toy_http_server.py [port]

Inspect it with mcp-audit:
    uv run mcp-audit inspect -- http://127.0.0.1:8000/mcp

Scan it with mcp-audit (expect a transport-security AND an
unauthenticated-discovery finding, since it's plain http:// with no auth):
    uv run mcp-audit scan -- http://127.0.0.1:8000/mcp
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from toy_server import server  # noqa: E402 - sys.path must be set up first

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server.run(transport="streamable-http", host="127.0.0.1", port=port)
