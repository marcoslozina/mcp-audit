"""Check: unauthenticated discovery surface on a remote transport.

This is a distinct risk from `transport-security`: an endpoint can use
`https://` (transport encrypted, `transport-security` passes) and still
hand its entire `initialize`/`list_tools` surface — every tool name,
description, and input schema, plus any resources/prompts — to anyone who
simply reaches the URL, before any authentication step. Encrypted-in-
transit is not the same question as "who can see this".

Not applicable to stdio: a local subprocess spawned by mcp-audit itself has
no discovery handshake to gate behind auth in the first place — there's no
"anyone who reaches it", just the parent process that spawned it.

What this check can and cannot actually verify
------------------------------------------------
`mcp_audit.parser.inspect_http_server` connects to the target with zero
headers of any kind — mcp-audit has no CLI-level way to supply credentials
today. That means, by construction:

- If a `ServerSnapshot` exists for an http(s) target at all, the
  `initialize`/`list_tools` handshake just succeeded with no
  `Authorization` header (or any other auth material) attached. That's
  exactly the condition this check reports as a finding.
- If the server correctly requires auth, the handshake itself fails before
  a snapshot is ever produced (mcp-audit reports that as a connection
  error further up the stack, in `cli._run_scan_report`) — the expected,
  non-finding outcome, but one this check never gets a chance to grade,
  since it only runs against a snapshot that already exists.

This check only proves "the handshake completes with *no* auth header
sent". It does NOT prove "this server has no authentication of any kind" —
a server could still gate actual tool *invocations* (as opposed to listing
them), or authenticate via a scheme this probe never attempts (mTLS,
cookies, a query-string API key, an IP allowlist). Treat a clean result
here as "no auth was required to see the surface", not as a general
authentication audit.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.base import Check, CheckOutcome, Finding
from mcp_audit.parser import ServerSnapshot

CHECK_ID = "unauthenticated-discovery"


class UnauthenticatedDiscoveryCheck(Check):
    check_id = CHECK_ID
    name = "Unauthenticated discovery surface"

    def run(self, snapshot: ServerSnapshot, source_dir: Path | None = None) -> CheckOutcome:
        if snapshot.transport == "stdio":
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="not_applicable",
                reason=(
                    "server was inspected over stdio (local subprocess pipes); "
                    "there is no remote discovery handshake to gate behind auth "
                    "for a process mcp-audit spawned itself. This check activates "
                    "automatically for a remote (http/https) target."
                ),
            )

        surface = (
            f"{len(snapshot.tools)} tool(s), {len(snapshot.resources)} resource(s), {len(snapshot.prompts)} prompt(s)"
        )
        endpoint_url = snapshot.endpoint_url or snapshot.server_name
        finding = Finding(
            severity="high",
            check_id=self.check_id,
            title="Server exposes initialize/list_tools with no authentication",
            description=(
                f"mcp-audit completed the initialize/list_tools handshake against "
                f"'{endpoint_url}' while sending no Authorization header or any other "
                f"auth material, and the server handed back its full discovery surface "
                f"({surface}) anyway. Anyone who finds this URL can enumerate the "
                f"server's complete tool/resource/prompt list, descriptions included, "
                f"with no credentials at all. Note: this check only verifies that "
                f"*no* auth header was required to complete discovery — it does not "
                f"rule out auth being enforced on actual tool calls, or via a scheme "
                f"this probe doesn't attempt (mTLS, cookies, query-string API keys)."
            ),
            location=endpoint_url,
        )

        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            reason=(
                f"server was inspected over http at '{endpoint_url}' with no auth "
                "headers sent, and the handshake succeeded."
            ),
            findings=[finding],
        )
