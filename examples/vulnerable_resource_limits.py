"""Fixture with no rate-limiting on a tool that calls a paid external API,
used to exercise mcp_audit's `ResourceLimitsCheck` (source-level portion)
end-to-end via `mcp-audit scan --source-dir`.

Not a real MCP server, not something to run — purely a static fixture,
parsed only via `ast` the same way `vulnerable_path_traversal.py` and
`vulnerable_scope.py` are. `call_translation_api` wraps a metered
third-party API with no rate-limiting library, decorator, or budget check
anywhere in this file — an agent that calls this tool in a loop (by
mistake, or because it was manipulated into doing so) runs up an unbounded
bill with nothing here to stop it. Do not model a real tool handler on
this.
"""

from __future__ import annotations

import requests


class _FakeMCP:
    def tool(self):  # type: ignore[no-untyped-def]
        def decorator(func):  # type: ignore[no-untyped-def]
            return func

        return decorator


mcp = _FakeMCP()


@mcp.tool()
def call_translation_api(text: str, target_language: str) -> str:
    """Translate text into another language using a third-party translation API.

    Args:
        text: The text to translate
        target_language: Target language code (e.g. 'es', 'fr')

    Returns:
        The translated text.
    """
    # VULNERABLE (by omission): no rate limiting, throttling, or per-call
    # budget anywhere in this file. Every call to this tool hits a metered,
    # paid third-party endpoint with nothing to cap how often that happens.
    response = requests.post(
        "https://api.example-translate.com/v1/translate",
        json={"text": text, "target": target_language},
        timeout=10,
    )
    return response.json()["translated_text"]
