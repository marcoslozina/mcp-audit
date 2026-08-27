"""HTTP variant of toy_server.py gated behind a minimal bearer-token check,
used to exercise the "expected, non-finding" branch of
`unauthenticated-discovery`: a real MCP endpoint that correctly rejects a
caller sending no credentials.

This is NOT a real OAuth implementation (see `mcp.server.auth` for that,
which this deliberately does not touch) — it's the smallest possible ASGI
middleware that returns 401 before a request reaches MCPServer's own
Streamable HTTP app, wrapped around the *same* unmodified `server` object
from toy_server.py via `streamable_http_app()`. Good enough to prove that
mcp-audit's HTTP client (which sends zero auth headers, see
`mcp_audit.parser.inspect_http_server`) gets a real, live connection
failure here rather than a snapshot — the correct outcome, not a finding.

Run standalone:
    python examples/toy_http_server_authed.py [port]

Confirm mcp-audit's scan reports a connection error (not findings) against it:
    uv run mcp-audit scan -- http://127.0.0.1:8001/mcp
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import uvicorn  # noqa: E402
from starlette.responses import PlainTextResponse  # noqa: E402
from starlette.types import ASGIApp, Receive, Scope, Send  # noqa: E402
from toy_server import server  # noqa: E402 - sys.path must be set up first

REQUIRED_TOKEN = "test-only-token-not-a-real-secret"  # noqa: S105 - test fixture only


class RequireBearerToken:
    """Rejects any HTTP request that doesn't carry `Authorization: Bearer
    <REQUIRED_TOKEN>`, before it reaches the wrapped MCP app. Passes
    non-http scopes (in particular "lifespan") straight through, since the
    wrapped Starlette app's own session-manager startup/shutdown depends on
    receiving those events untouched.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope["headers"])
        auth_header = headers.get(b"authorization", b"").decode("latin-1")
        if auth_header != f"Bearer {REQUIRED_TOKEN}":
            response = PlainTextResponse("Unauthorized", status_code=401)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8001
    inner_app = server.streamable_http_app(host="127.0.0.1")
    app = RequireBearerToken(inner_app)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
