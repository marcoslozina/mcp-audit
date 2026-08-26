"""Check: insecure transport (TLS / declared auth mechanism).

mcp-audit's parser currently only speaks stdio (spawning the target as a
local subprocess and talking JSON-RPC over its pipes — see
`mcp_audit.parser.inspect_server`). Stdio has no notion of TLS or bearer
auth: the "transport security" question a check like this exists to ask
("is this connection encrypted?", "is there an auth mechanism declared?")
simply doesn't have an answer when the channel is a local pipe between a
parent and a child process it spawned itself.

Reporting this check as "passed" in that situation would be dishonest —
it would look identical, in a report, to "we checked, and this server's
HTTP endpoint correctly requires HTTPS + auth". So instead this check
reports itself as NOT APPLICABLE whenever the snapshot's transport is
stdio, with an explicit reason, and is structured so that once the parser
gains HTTP/SSE support (tracked as future work), the real logic below
starts running automatically instead of requiring a rewrite.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.base import Check, CheckOutcome, Finding
from mcp_audit.parser import ServerSnapshot

CHECK_ID = "transport-security"

_INSECURE_URL_PREFIX = "http://"


class TransportCheck(Check):
    check_id = CHECK_ID
    name = "Insecure transport / missing auth"

    def run(self, snapshot: ServerSnapshot, source_dir: Path | None = None) -> CheckOutcome:
        if snapshot.transport == "stdio":
            return CheckOutcome(
                check_id=self.check_id,
                name=self.name,
                status="not_applicable",
                reason=(
                    "server was inspected over stdio (local subprocess pipes); "
                    "there is no network transport, TLS, or auth mechanism to "
                    "evaluate for this connection. This check will activate once "
                    "mcp-audit's parser supports HTTP/SSE transports."
                ),
            )

        # --- Future path: only reachable once the parser supports a
        # remote transport and starts recording things like
        # snapshot.transport == "http"/"sse" and the endpoint URL / declared
        # auth scheme. Left here, unexercised, so the check's intent and
        # shape are already in place rather than invented from scratch later.
        findings: list[Finding] = []
        endpoint_url = getattr(snapshot, "endpoint_url", None)
        if endpoint_url and endpoint_url.startswith(_INSECURE_URL_PREFIX):
            findings.append(
                Finding(
                    severity="high",
                    check_id=self.check_id,
                    title="Server reachable over plaintext HTTP",
                    description=(
                        f"Endpoint '{endpoint_url}' uses http:// instead of https://, "
                        "so traffic (including any auth tokens) is unencrypted."
                    ),
                    location=endpoint_url,
                )
            )

        declared_auth = getattr(snapshot, "declared_auth", None)
        if not declared_auth:
            findings.append(
                Finding(
                    severity="medium",
                    check_id=self.check_id,
                    title="No auth mechanism declared",
                    description=(
                        "The server did not declare an authentication mechanism "
                        "for its remote transport."
                    ),
                    location=snapshot.server_name,
                )
            )

        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            findings=findings,
        )
