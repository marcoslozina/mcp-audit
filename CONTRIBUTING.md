# Contributing to mcp-audit

Thanks for considering a contribution. This is a solo-maintained, open-source
project — issues and PRs are genuinely welcome, especially new checks for
MCP-specific attack classes that aren't covered yet.

If you're an AI coding agent working in this repo, read
[`AGENTS.md`](AGENTS.md) first — it covers codebase-specific gotchas (SDK
attribute naming, docstring vs. f-string pitfalls, flag-ordering rules) that
this file doesn't repeat.

## Setting up the environment

```bash
git clone https://github.com/marcoslozina/mcp-audit
cd mcp-audit
uv sync
```

`uv sync` reads `pyproject.toml` and `uv.lock` and creates a `.venv` with
every runtime and dev dependency (`pytest`, `pytest-asyncio`, `ruff`,
`mypy`). There's no separate bootstrap step.

Run the CLI itself via `uv run`, never a bare `mcp-audit` unless you've
activated the venv:

```bash
uv run mcp-audit scan -- python examples/toy_server.py
```

## Running the checks locally

Run all three of these before opening a PR — they're exactly what CI runs
(see [CI expectations](#ci-expectations) below).

**Tests** (pytest, `tests/`):

```bash
uv run pytest -v
```

**Lint** (ruff, config in `pyproject.toml`'s `[tool.ruff]`):

```bash
uvx ruff check .
```

**Type-check** (mypy, scoped to `src/`, config in `pyproject.toml`'s
`[tool.mypy]`):

```bash
uv run mypy src/
```

mypy here is deliberately not `--strict` — it's tuned to catch real type
errors (missing annotations, wrong argument types, mismatched literals)
without demanding exhaustive generics/`Any` discipline on a project this
size. If you add code that needs a `# type: ignore`, leave a comment
explaining why rather than silencing the error bare.

Also worth running manually, since they exercise the real CLI end-to-end the
way the smoke-test CI job does:

```bash
uv run mcp-audit scan -- python examples/toy_server.py   # expect: clean pass, exit 0
uv run mcp-audit scan -- python examples/evil_server.py  # expect: caught, exit 1
```

## Commit conventions

- **Conventional Commits** format: `feat:`, `fix:`, `docs:`, `chore:`,
  `ci:`, `test:`, `refactor:`, etc.
- **No AI attribution in commit messages.** Don't add
  `Co-Authored-By: Claude`, `Co-Authored-By: <any AI>`,
  "Generated with [tool]", or anything similar — even if an AI assistant
  helped write the change. This is a strict project rule (see
  [`AGENTS.md`](AGENTS.md#commit-conventions)), not a style preference.
  Commit messages describe the change, not the tooling used to produce it.

## Adding a new security check

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

Steps:

1. Create `src/mcp_audit/checks/your_check.py`, implement `Check`. Return a
   `CheckOutcome` (`src/mcp_audit/checks/base.py`) carrying a list of
   `Finding`s (`severity`, `check_id`, `title`, `description`, `location`).

2. Get `CheckOutcome.status` right — this is a product requirement, not
   plumbing:
   - `"ran"` — the check executed its full logic against real input.
   - `"skipped"` — the check *could* run but the user didn't provide what
     it needed (e.g. `SecretsCheck` without `--source-dir`). The user can
     fix this by re-running with more input.
   - `"not_applicable"` — the check's precondition isn't met by this scan
     at all (e.g. `TransportCheck` against a stdio connection, which has no
     TLS/auth to evaluate). This is **not** the same as "passed" — nothing
     was verified either way.

3. Register it, following how the existing checks are wired in
   `src/mcp_audit/checks/__init__.py` and `src/mcp_audit/cli.py`:
   - **Stateless** checks (only need the `ServerSnapshot` — like
     `UnicodeConcealmentCheck`, `SecretsCheck`, `TransportCheck`): instantiate
     the class and add it to the `ALL_CHECKS` list in
     `src/mcp_audit/checks/__init__.py`. `cli.py`'s `scan` command runs
     everything in `ALL_CHECKS` automatically — no CLI changes needed.
   - **Stateful** checks that need CLI-provided input before construction
     (like `RugPullCheck`, which needs a resolved `server_id` and the
     `--update-baseline` flag): don't add them to `ALL_CHECKS`. Instead,
     instantiate them per-invocation inside `cli.py`'s `scan` command, the
     way `RugPullCheck` is built there, then append the instance to the
     list of checks actually run for that invocation. Still export the
     class from `checks/__init__.py`'s `__all__` so `cli.py` doesn't need
     to import the submodule directly.

4. Pick severity honestly: `critical`/`high` findings gate CI (`scan` exits
   `1`); `medium`/`low` don't. Don't mark something `critical` just to make
   sure it gets noticed if it's genuinely informational — see how
   `RugPullCheck` grades a changed tool definition (`high`) differently
   from a newly-added one (`medium`) or a removed one (`low`).

5. Add tests under `tests/checks/` — one file per check, following the
   existing pattern (`tests/checks/test_unicode_concealment.py` and
   `tests/checks/test_transport.py` build synthetic `ServerSnapshot`
   objects directly; `tests/checks/test_secrets.py` and
   `tests/checks/test_rug_pull.py` are more integration-flavored because
   those checks inherently touch disk/state).

6. If your check changes the JSON report's *shape* in a breaking way (a
   field removed or repurposed, not just added), bump `_SCHEMA_VERSION` in
   `src/mcp_audit/cli.py` and update the corresponding note in
   `README.md`. Adding a new field is additive and doesn't need a bump.

## CI expectations

Every PR runs three GitHub Actions workflows:

- **`tests.yml`** — `uvx ruff check .`, `uv run mypy src/`, and
  `uv run pytest -v`.
- **`smoke-test.yml`** — runs the real CLI against `examples/toy_server.py`
  (must exit `0`, clean) and `examples/evil_server.py` (must exit `1`,
  caught) as an end-to-end sanity check independent of the pytest suite.

A PR needs all of these green before it's merged. If you touch
`checks/rug_pull.py`, double-check the test suite still never reads or
writes the real developer's `~/.mcp-audit/baselines` — see the "Test
isolation for the rug-pull baseline" note in `AGENTS.md`.

## Reporting security issues

Found a vulnerability *in* `mcp-audit` itself, rather than a check missing
an attack class? See [`SECURITY.md`](SECURITY.md) — that goes through
GitHub Security Advisories, not a public issue.
