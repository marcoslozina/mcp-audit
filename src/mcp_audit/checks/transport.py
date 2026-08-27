"""Check: insecure transport (plaintext HTTP).

For a stdio target (spawning the target as a local subprocess and talking
JSON-RPC over its pipes — see `mcp_audit.parser.inspect_server`), there is
no notion of TLS: the "is this connection encrypted?" question this check
exists to ask simply doesn't have an answer when the channel is a local
pipe between a parent and a child process it spawned itself. Reporting
"passed" in that situation would be dishonest — it would look identical, in
a report, to "we checked, and this server's HTTP endpoint correctly uses
TLS". So this check reports itself as NOT APPLICABLE whenever the
snapshot's transport is stdio.

For an http target (`mcp_audit.parser.inspect_http_server`, Streamable
HTTP per MCP spec 2025-06-18), this check runs for real: `https://` passes
(the transport is encrypted), `http://` is a finding. Severity is `high`,
not `critical` — this is a network-position-dependent MITM/eavesdropping
risk (anyone able to observe the connection can read tool-call arguments,
results, and any bearer token sent alongside them), the same tier as
`path-traversal`, not an immediately-exploitable payload the way
`unicode-concealment` or an unsanitized `shell=True` call is.

This check is scoped narrowly to "is the transport itself encrypted". It
deliberately does NOT also judge whether the server requires
authentication — that's a distinct question (an HTTPS endpoint can still
hand its entire tool/resource/prompt list to anyone who finds the URL) and
is covered by the separate `unauthenticated-discovery` check instead of
being folded in here as a second, unrelated finding.
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
                    "there is no network transport or TLS to evaluate for this "
                    "connection. This check activates automatically for a "
                    "remote (http/https) target."
                ),
            )

        findings: list[Finding] = []
        endpoint_url = snapshot.endpoint_url or ""
        if endpoint_url.startswith(_INSECURE_URL_PREFIX):
            findings.append(
                Finding(
                    severity="high",
                    check_id=self.check_id,
                    title="Server reachable over plaintext HTTP",
                    description=(
                        f"Endpoint '{endpoint_url}' uses http:// instead of https://, "
                        "so traffic (including tool-call arguments, results, and any "
                        "bearer token sent alongside them) is unencrypted and can be "
                        "read or tampered with by anyone able to observe the connection."
                    ),
                    location=endpoint_url,
                )
            )

        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            reason=(
                f"server was inspected over http at '{endpoint_url}'; transport "
                + ("is unencrypted (http://)." if findings else "is encrypted (https://).")
            ),
            findings=findings,
        )
