# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `.github/workflows/traffic-archive.yml`: a daily scheduled workflow (plus
  manual `workflow_dispatch`) that archives GitHub's repo traffic data
  (views/clones) to `data/traffic-history.jsonl`, since GitHub's traffic API
  only retains 14 days of history. Requires a `TRAFFIC_PAT` repository
  secret (fine-grained PAT, `Administration: Read-only`) — the automatic
  `GITHUB_TOKEN` cannot be granted that permission, confirmed empirically
  (see the workflow file's header comment).

## [0.1.0] - 2026-08-27

Initial public release: a CLI that connects to an MCP server over stdio,
inspects what it exposes, and runs eight security checks against that
snapshot.

### Added

- Core stdio parser and CLI scaffold: `mcp-audit inspect` / `mcp-audit scan`
  connect to a target MCP server the same way an AI client would and build a
  `ServerSnapshot` of its tools, resources, and prompts.
- Eight security checks, each implementing a shared `Check` interface and
  reporting an honest `ran` / `skipped` / `not_applicable` status alongside
  its findings:
  - **unicode-concealment** — Unicode TAG-block and other invisible/bidi
    concealment payloads hidden in tool/resource/prompt descriptions.
  - **secrets** (hardcoded secrets) — vendor API key formats, secret-like
    assignments, and high-entropy string literals, via `--source-dir`.
  - **transport** — plaintext/missing-auth transport checks, honestly
    reported as `not_applicable` for the current stdio-only transport.
  - **rug-pull** — detects a tool's description or input schema changing
    after a user already approved it, by diffing against a saved baseline
    in `~/.mcp-audit/baselines/` (`--server-id`, `--update-baseline`).
  - **code-injection** — `subprocess`/`os.system(shell=True)`,
    `eval`/`exec`, and string-built SQL, via `--source-dir`, built on top
    of `bandit`'s Python API rather than hand-rolled regex.
  - **path-traversal** — purpose-built AST check for MCP tool/resource
    handlers passing unsanitized input into `open()`, via `--source-dir`.
  - **overprivileged-scopes** — tools whose declared/actual access exceeds
    what their name or description implies, checked at both the protocol
    level (always runs) and the source level (`--source-dir`).
  - **resource-limits** — whether anything bounds how often a tool can be
    called; protocol-level honestly reports `not_applicable` (no
    standardized rate-limit mechanism in the MCP spec), source-level looks
    for known rate-limiting libraries via `--source-dir`.
- `scan` command: human-readable `rich` report (severity-colored findings
  plus a per-check coverage table) and `--format json` for CI/CD gating,
  exiting `1` on any critical/high finding. JSON reports carry a
  `schema_version` field for consumers to detect breaking shape changes.
- `badge` command: reduces a scan to a shields.io endpoint-badge JSON
  payload, for a self-hosted "scanned with mcp-audit" README badge.
- Example fixtures under `examples/`: a clean `toy_server.py`, an
  `evil_server.py` carrying a Unicode-concealment payload, and
  source-only fixtures (`vulnerable_config.py`, `vulnerable_command.py`,
  `vulnerable_path_traversal.py`, `vulnerable_scope.py`,
  `vulnerable_resource_limits.py`) exercising each `--source-dir` check.
  Example GitHub Actions workflows (`examples/github-actions/`) showing
  how to run `mcp-audit` as a consumer CI gate and how to publish the
  `badge` output.
- Automated test suite (`pytest`, `pytest-asyncio`): stdio integration
  tests against `toy_server.py`, unit tests per check under
  `tests/checks/`, subprocess-based end-to-end CLI tests including
  `--format json`, and badge-output tests.
- CI: a `smoke-test.yml` workflow running the real CLI against
  `toy_server.py` (expects clean) and `evil_server.py` (expects caught) on
  every push/PR; a `tests.yml` workflow running `ruff`, `mypy`, and
  `pytest`; CodeQL static analysis via GitHub's default code-scanning
  setup.
- Local safety net: `.pre-commit-config.yaml` running `ruff` (lint +
  format), `mypy`, and a `gitleaks` secret scan on every commit, with the
  full `pytest` suite on pre-push.
- Documentation: `README.md` (product pitch, checks table, real-world
  detections against official MCP reference servers and against the Damn
  Vulnerable MCP Server training lab, CI usage, badge setup, sustainability
  section), `AGENTS.md` (codebase conventions and SDK gotchas for AI coding
  agents), `CONTRIBUTING.md` (environment setup, how to add a new check, CI
  expectations), `SECURITY.md` (private vulnerability reporting via GitHub
  Security Advisories), `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1),
  and the MIT `LICENSE`.
- `.github/FUNDING.yml` (Buy Me a Coffee).

### Changed

- Factored the scan pipeline into a shared `_run_scan_report` helper so
  `scan` and `badge` run the same connect-and-check logic instead of
  duplicating it.
- Applied `ruff format` across `src/` and `tests/` to match the pinned
  formatter version enforced by the new pre-commit hook.

### Fixed

- `RugPullCheck` baselines are now isolated from the real developer's
  `~/.mcp-audit/baselines` in tests, via an `MCP_AUDIT_BASELINE_DIR`
  environment variable override checked at construction time.
- `scan --format json` no longer swallows handshake/transport failures
  (target command not found, protocol mismatch) as plain-text stderr —
  these now emit a structured JSON error object on stdout so CI tooling
  can always `json.loads()` the output.
- Assorted documentation drift between `README.md`, `AGENTS.md`, and
  `CONTRIBUTING.md` (stale placeholders, an inaccurate workflow count, an
  incorrect claim about how `ruff` is installed).

[Unreleased]: https://github.com/marcoslozina/mcp-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/marcoslozina/mcp-audit/releases/tag/v0.1.0
