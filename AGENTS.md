# AGENTS.md

Instructions for AI coding agents (Claude Code, GitHub Copilot, Aider, Cursor,
etc.) working in this repository. This follows the [agents.md](https://agents.md)
convention — plain Markdown, no rigid schema, read it before touching code.

## What this project is

`mcp-audit` is a security scanner for MCP (Model Context Protocol) servers.
It connects to a target server the same way an AI client would (currently
stdio only), inspects what it exposes (tools/resources/prompts), and runs
checks against that snapshot. See `README.md` for the product pitch — this
file is about how to work in the codebase, not what it does for users.

## Setup

```bash
uv sync
```

That's it — `uv` reads `pyproject.toml` and `uv.lock` and creates `.venv`.

Optionally (but see "Mandatory: run pre-commit yourself before proposing any
commit" below for why this doesn't replace anything):

```bash
uv run pre-commit install
uv run pre-commit install --hook-type pre-push
```

## Running the CLI

Always through `uv run`, never a bare `mcp-audit` unless you've activated the
venv yourself:

```bash
uv run mcp-audit inspect -- python examples/toy_server.py
uv run mcp-audit scan -- python examples/toy_server.py
uv run mcp-audit scan --format json -- python examples/toy_server.py
```

### Critical rule: mcp-audit's own flags go BEFORE `--`

```bash
# Correct
uv run mcp-audit scan --source-dir ./src --server-id my-server -- python server.py

# Wrong: --source-dir here is argv the TARGET SERVER receives, not an
# option mcp-audit reads.
uv run mcp-audit scan -- python server.py --source-dir ./src
```

**Why**: `server_command` is declared as a Click `nargs=-1` argument
capturing everything after `--`. That whole tail is handed to the target
server's process as its own argv, unparsed by Click — mcp-audit has no
mechanism to distinguish "an option I should read" from "an argument the
server happens to receive" once you're past `--`, because at that point
those bytes are none of mcp-audit's business by design (it has to pass them
through literally, since it doesn't know what the target server expects).
There's a heuristic warning (`_warn_misplaced_flags` in `cli.py`) that fires
on stderr if one of mcp-audit's own flag names (`--source-dir`,
`--server-id`, `--update-baseline`, `--format`) turns up after `--`, but
don't rely on it catching every case — get the order right instead.

## Running the example servers / fixtures

- `examples/toy_server.py` — clean baseline server, exercises tools,
  resources, and prompts. Should always come back with **no findings**.
  ```bash
  uv run mcp-audit scan -- python examples/toy_server.py
  ```
- `examples/evil_server.py` — identical to `toy_server.py` except one tool
  description carries a payload hidden in the Unicode TAG block
  (`U+E0000`–`U+E007F`). Should always be **caught** (exit code 1, a
  `unicode-concealment` critical finding). If a change makes this scan come
  back clean, the detector broke — this is exactly what
  `.github/workflows/smoke-test.yml` asserts on every push/PR.
  ```bash
  uv run mcp-audit scan -- python examples/evil_server.py
  ```
- `examples/vulnerable_config.py` — not an MCP server, just a fixture file
  with an obviously fake hardcoded API key and DB URL, used to exercise
  `SecretsCheck` via `--source-dir`:
  ```bash
  uv run mcp-audit scan --source-dir examples -- python examples/toy_server.py
  ```
- `examples/vulnerable_command.py` — fixture with a `shell=True` command
  built from an f-string, used to exercise `CodeInjectionCheck` (bandit-backed)
  via `--source-dir`. Not run as a server, only scanned as source.
- `examples/vulnerable_path_traversal.py` — fixture with a fake `@mcp.tool()`
  handler that joins a parameter into a path and opens it with no
  realpath/resolve check, used to exercise `PathTraversalCheck` via
  `--source-dir`. Only ever parsed via `ast`, never imported/executed.
- `examples/vulnerable_scope.py` — fixture with a fake `@mcp.tool()` handler
  (`check_service_status`) whose name/docstring promise a narrow read-only
  status check but whose body shells out via `subprocess` and writes a log
  file — exercises `OverprivilegedScopesCheck`'s source-level portion via
  `--source-dir`. Only ever parsed via `ast`, never imported/executed.
- `examples/vulnerable_resource_limits.py` — fixture with a fake
  `@mcp.tool()` handler that calls a metered third-party API via `requests`
  with no rate-limiting library/decorator anywhere in the file — exercises
  `ResourceLimitsCheck`'s source-level portion via `--source-dir`. Only
  ever parsed via `ast`, never imported/executed.

## Known SDK gotchas (things we already got burned by)

These aren't hypothetical — they cost real debugging time during this
project's development. Don't repeat them.

1. **`mcp` SDK v2.1.1 uses snake_case attributes, not the wire format's
   camelCase.** The MCP JSON-RPC wire protocol uses `inputSchema`,
   `mimeType`, etc., but the Python SDK's parsed objects expose
   `tool.input_schema`, `resource.mime_type`, and so on. If you're adding a
   new field from an SDK response object, check the actual attribute name on
   the object (or the SDK's type stubs) — don't assume it matches the raw
   JSON key you see in a protocol trace, and don't assume it matches
   whatever a different mcp SDK version once used.

2. **An f-string is not a valid docstring / doesn't populate `__doc__`.**
   A docstring must be a literal, compile-time constant — Python only wires
   up `__doc__` when the first statement of a function/module is a plain
   string literal, not an f-string (which is evaluated at runtime and is
   technically an expression, not a literal). This came up building
   `examples/evil_server.py`: the hidden Unicode-TAG payload has to be
   concatenated onto a tool's description, and that has to be done via the
   explicit `description=` keyword argument on `@server.tool(...)`, not by
   f-string-formatting the function's docstring — the latter would silently
   not do what you want. If you ever need a computed/dynamic description or
   docstring-like string, pass it explicitly rather than relying on
   docstring introspection.

## Code structure: adding a new check

Checks live in `src/mcp_audit/checks/` and implement the `Check` interface
defined in `src/mcp_audit/checks/base.py`:

```python
class Check(ABC):
    check_id: str
    name: str

    @abstractmethod
    def run(self, snapshot: ServerSnapshot, source_dir: Path | None = None) -> CheckOutcome:
        ...
```

A `CheckOutcome` reports one of three statuses, and the distinction is a
product requirement, not a technicality — see the docstring in `base.py`:

- `"ran"` — the check executed its full logic against real input.
- `"skipped"` — the check could run in principle, but the user didn't
  provide what it needed (e.g. no `--source-dir` for `SecretsCheck`).
  The user can fix this by re-running with more input.
- `"not_applicable"` — the check's precondition isn't met by this scan at
  all (e.g. transport-security checks against a stdio-only connection).
  This is **not** the same as "passed" — nothing was verified either way.

For the full step-by-step (where to register it, stateless vs. stateful
checks, severity guidance, test file conventions, when to bump
`_SCHEMA_VERSION`), see CONTRIBUTING.md's ["Adding a new security
check"](CONTRIBUTING.md#adding-a-new-security-check) — kept in one place so
the two files don't drift out of sync with each other.

## JSON output contract (`scan --format json`)

The JSON report includes a `"schema_version"` integer field (currently `1`).
If you change the report's shape in `cli.py` (`_build_report` /
`_build_error_report`) in a way that removes or repurposes a field, bump
`_SCHEMA_VERSION` in `cli.py` and update the corresponding note in
`README.md`. Adding a new field is additive, not breaking — no bump needed
for that.

Errors (target command not found, handshake/protocol failure, etc.) under
`--format json` must also come out as parseable JSON on stdout with an
`"error"` field, not a plain-text message or an unhandled traceback — CI
tooling consuming this format needs to be able to `json.loads()` it
unconditionally. See `_fail_scan` in `cli.py`.

## Commit conventions

- **Conventional Commits** format (`feat:`, `fix:`, `docs:`, `chore:`,
  `ci:`, etc.).
- **No AI attribution in commits.** Do not add `Co-Authored-By: Claude`,
  `Co-Authored-By: <any AI>`, "Generated with [tool]", or any similar
  attribution line to commit messages. This is a strict, explicit
  project rule — not a style preference. Commit messages describe the
  change; they don't describe the tooling that helped write it.

## Mandatory: run pre-commit yourself before proposing any commit

This repo has a `.pre-commit-config.yaml` (ruff lint + format check, mypy,
gitleaks secret scan) meant to run as a git hook on every commit, and pytest
on every push. **Do not assume that hook fired.** A git hook only runs when
a commit is made through git's own commit machinery on a checkout where
`pre-commit install` has already been run — neither of those is guaranteed
to be true for you:

- You may be composing a commit through a mechanism that doesn't go through
  the local git hook at all.
- `pre-commit install` is a one-time, per-checkout, local step — a fresh
  clone or a fresh agent sandbox has the config file (it's committed) but
  not the installed hook (that part is never committed, by design — see
  `pre-commit`'s own docs).

So, as an agent, before you hand back a commit as done:

```bash
uv run pre-commit run --all-files
```

Run this explicitly, every time, regardless of whether you think the git
hook already ran. If it fails, fix what it found — don't commit around it,
and don't pass `--no-verify` to skip it. This is what makes the local
safety net actually agent-first: it doesn't rely on a human remembering to
run it, or on a hook silently not being installed — it's a step spelled out
right here for any agent reading this file.

## Testing

There is a pytest suite under `tests/`, run via:

```bash
uv run pytest -v
```

- `tests/test_parser.py` — integration tests that connect for real to
  `examples/toy_server.py` over stdio (no mocking) and assert on the
  resulting `ServerSnapshot`.
- `tests/checks/` — one file per check. Unit tests where possible
  (`test_unicode_concealment.py`, `test_transport.py` build synthetic
  `ServerSnapshot`/`ToolInfo` objects directly), integration-flavored where
  the check inherently touches disk/state (`test_secrets.py` runs against
  `examples/vulnerable_config.py`; `test_rug_pull.py` exercises baseline
  create/compare/update against `tmp_path`).
- `tests/test_cli.py` — end-to-end tests that invoke the CLI as a real
  subprocess (`python -m mcp_audit.cli ...`) against `toy_server.py` and
  `evil_server.py`, including `--format json` output validity.
- `tests/test_badge.py` — same subprocess approach, for the `badge` command:
  asserts the shields.io endpoint-badge JSON shape and colors for a clean
  scan (`brightgreen`/`passing`) and a caught one (`red`/`critical/high`).

**Test isolation for the rug-pull baseline**: `RugPullCheck` stores baselines
under `~/.mcp-audit/baselines` by default (see `checks/rug_pull.py`). Any
test that goes through the CLI (which constructs `RugPullCheck` internally
without a `baseline_dir`) MUST set the `MCP_AUDIT_BASELINE_DIR` env var to a
temp directory first — the `baseline_dir_env` fixture in `tests/conftest.py`
does this. Tests that construct `RugPullCheck` directly can instead pass
`baseline_dir=tmp_path`. Either way, the test suite must never read or write
the real developer's home directory — verify this if you touch
`rug_pull.py`.

Lint via `ruff` (`pyproject.toml` `[tool.ruff]`):

```bash
uvx ruff check .
```

Static type-checking via `mypy` (`pyproject.toml` `[tool.mypy]`), scoped to
`src/` only — deliberately not `--strict`, per the same "don't gold-plate"
philosophy as the ruff config, but enough to catch real type errors (missing
annotations, wrong argument types):

```bash
uv run mypy src/
```

`uv run pytest`, `uvx ruff check .`, and `uv run mypy src/` all run in CI on
every push/PR — see `.github/workflows/tests.yml`. The smoke test in
`.github/workflows/smoke-test.yml` (real CLI against the example servers,
asserting exit codes) still runs separately and independently; it remains
valuable as an end-to-end check even with the pytest suite in place. Before
submitting a change, run the pytest suite, ruff, mypy, and the two
smoke-test scans locally.
