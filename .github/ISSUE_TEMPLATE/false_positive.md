---
name: False positive report
about: A heuristic check flagged something that doesn't actually apply
title: "false positive: "
labels: false-positive
assignees: ""
---

<!-- README.md is explicit that path-traversal, overprivileged-scopes, and
     resource-limits are heuristic checks with documented false positives
     and false negatives. This template is for reporting one so it can be
     tuned or, at minimum, documented alongside the existing examples. -->

## Which check

<!-- One of: path-traversal / overprivileged-scopes / resource-limits / other
     (name it) -->

## Exact command you ran

```bash
uv run mcp-audit scan --source-dir ... -- python ...
```

## The finding

<!-- Paste the finding as reported (title, description, location) — from
     the human report or the `--format json` output. -->

## Why it doesn't apply

<!-- Explain the actual code path: why the flagged pattern is safe here
     (e.g. sanitization the check can't see, a false taint assumption, a
     privilege the tool's description does legitimately need). Include the
     relevant source snippet if you can share it. -->

## Source file (if shareable)

<!-- Attach or paste the minimal relevant portion of the flagged file. Not
     required if it's proprietary — a description of the pattern is enough
     to start a discussion, but a real snippet makes it much faster to fix. -->
