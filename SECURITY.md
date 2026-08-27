# Security Policy

`mcp-audit` is a security tool, so its own security bar has to be higher than
average — please report vulnerabilities responsibly rather than opening a
public issue.

## Reporting a vulnerability

Use **GitHub Security Advisories**, not a public issue or PR:

**[Report a vulnerability](https://github.com/marcoslozina/mcp-audit/security/advisories/new)**

This is the preferred and currently only channel. It's private by
construction — the report and any discussion stay visible only to you and
the maintainer until a fix ships and you both agree to disclose — and it
costs nothing to use. Please don't post exploit details in a public GitHub
issue, a PR, or anywhere else public before a fix is available.

If your finding is about a specific check missing a real attack class
(false negative) rather than a vulnerability *in* `mcp-audit` itself, that's
a normal public issue, not a security report — the [Contributing
section](README.md#contributing) covers that case.

## Supported versions

`mcp-audit` is pre-1.0 and has no version support matrix yet. Only the
**latest commit on `main`** is supported — there are no maintained release
branches to backport a fix to. If you're running an older checkout, update
before reporting, if practical.

This section will gain an actual table once the project cuts a 1.0 and
starts maintaining more than one line at a time.

## Response time

This is a solo-maintained, open-source project run on volunteer time (not a
funded team with an on-call rotation). I'll do my best to acknowledge a
report within a few days and work a fix as a priority once confirmed, but
there's **no guaranteed SLA** at this stage — please plan around best-effort,
not a contractual response window. If you haven't heard back after a
reasonable wait, a polite follow-up on the same advisory thread is fine.
