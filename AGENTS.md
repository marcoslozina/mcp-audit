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
There's no separate lint/format/test bootstrap step yet (see "Testing" below
for what "tests" means at this stage).

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

To add a new check:

1. Create `src/mcp_audit/checks/your_check.py`, implement `Check`, return
   `Finding`s (see `Finding` dataclass in `base.py`: `severity`, `check_id`,
   `title`, `description`, `location`) plus an honest `CheckOutcome`.
2. Register it in `src/mcp_audit/checks/__init__.py`:
   - If it's stateless (only needs the `ServerSnapshot`), instantiate it and
     add it to the `ALL_CHECKS` list.
   - If it needs CLI-provided state before construction (like `RugPullCheck`
     needing a resolved `server_id`), instantiate it per-invocation in
     `cli.py`'s `scan` command instead, the way `RugPullCheck` is handled.
3. Severity guidance: `critical`/`high` findings gate CI (`scan` exits 1);
   `medium`/`low` don't. Pick accordingly — don't mark something `critical`
   just to make sure it's noticed if it's genuinely informational.

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

Both `uv run pytest` and `uvx ruff check .` run in CI on every push/PR — see
`.github/workflows/tests.yml`. The smoke test in
`.github/workflows/smoke-test.yml` (real CLI against the example servers,
asserting exit codes) still runs separately and independently; it remains
valuable as an end-to-end check even with the pytest suite in place. Before
submitting a change, run both the pytest suite and the two smoke-test scans
locally.
