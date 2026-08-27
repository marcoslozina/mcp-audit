---
name: Bug report
about: Something in mcp-audit itself is broken (crash, wrong exit code, bad output)
title: "bug: "
labels: bug
assignees: ""
---

## What happened

<!-- A clear description of the actual behavior. Include the full traceback
     or error message if there was one. -->

## What you expected instead

<!-- What you expected mcp-audit to do instead. -->

## Exact command you ran

```bash
uv run mcp-audit ...
```

<!-- Include the full command, flags and all. If it's specific to a target
     MCP server, mention which one (or attach a minimal reproduction server
     if it's not public). Remember mcp-audit's own flags go BEFORE `--`. -->

## mcp-audit version

<!-- `uv run mcp-audit --version` if the command supports it, otherwise the
     git commit SHA or tag you're on (`git rev-parse HEAD`). -->

## Relevant output

```
<!-- Paste the relevant stdout/stderr here. For --format json output,
     paste the raw JSON, not a paraphrase. -->
```

## Environment

- OS:
- Python version (`python --version`):
- Installed via (`uv sync` from a clone / `pip install` / other):
