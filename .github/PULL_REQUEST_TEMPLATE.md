## What this changes

<!-- Summary of the change and why it's needed. If it's a new check, link
     the attack class/CVE it covers. -->

## Checklist

- [ ] `uv run pytest -v` passes
- [ ] `uvx ruff check .` passes
- [ ] `uv run mypy src/` passes
- [ ] `uv run pre-commit run --all-files` is clean (this runs ruff,
      ruff-format, mypy, and gitleaks — see `CONTRIBUTING.md`)
- [ ] If this adds/changes a check: tests added under `tests/checks/`, and
      `CheckOutcome.status` (`ran` / `skipped` / `not_applicable`) is
      accurate for every path
- [ ] If this changes the JSON report's shape in a breaking way: bumped
      `_SCHEMA_VERSION` in `src/mcp_audit/cli.py` and updated the note in
      `README.md`
- [ ] Commit message(s) follow [Conventional Commits](https://www.conventionalcommits.org/)
      (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`, `refactor:`, ...)
- [ ] Commit message(s) contain **no AI attribution** (no `Co-Authored-By:
      Claude`, "Generated with [tool]", or similar — see
      `CONTRIBUTING.md#commit-conventions`)
- [ ] `CHANGELOG.md` updated under `[Unreleased]` if this is a
      user-visible change

## Related issue

<!-- Closes #... , if applicable -->
