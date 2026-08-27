# mcp-audit

Open-source security scanner for MCP (Model Context Protocol) servers — think
"Snyk for MCP servers." The long-term goal is a CLI that detects tool
poisoning, Unicode concealment attacks, rug-pulls, hardcoded secrets, insecure
transports, and other MCP-specific vulnerabilities, with an open-core model
(free CLI, future paid SaaS).

**This is an early-stage MVP.** Right now there are no security checks yet —
only the foundation: a parser that connects to a target MCP server over
stdio, performs the MCP handshake, and extracts its tools, resources, and
prompts into a structured snapshot that future checks will analyze.

## Install

```bash
uv sync
```

(or, without uv: `pip install -e .`)

## Usage

Inspect a target MCP server's capability surface:

```bash
uv run mcp-audit inspect -- python path/to/target_server.py
```

## Try it with the bundled toy server

A minimal MCP server with a few example tools lives in `examples/toy_server.py`,
used to verify the parser works end-to-end:

```bash
uv run mcp-audit inspect -- python examples/toy_server.py
```

This should print the toy server's `add`, `get_weather`, and `reverse_text`
tools, along with its one example resource and prompt.

## Rug-pull detection

`mcp-audit scan` compares the target server's tool definitions (name,
description, input schema) against a saved baseline from a previous scan,
to catch a server changing what a tool does *after* a user has already
approved it — e.g. a "read a file" tool quietly gaining delete behavior, or
a description subtly edited to inject instructions.

Baselines are stored per-server as JSON under `~/.mcp-audit/baselines/`
(home directory, not project-local, so they survive you running `mcp-audit`
from wherever). Each server is identified by a `--server-id` you choose, or,
if you don't pass one, a hash of the literal launch command — pass an
explicit `--server-id` if the command/args might change across runs of the
same logical server.

```bash
# First run: no baseline yet, one is created, nothing to compare.
uv run mcp-audit scan --server-id my-server -- python path/to/target_server.py

# Later runs: compared against the saved baseline. Tool description/schema
# changes are reported as HIGH findings; new tools as MEDIUM (informational);
# removed tools as LOW (informational).
uv run mcp-audit scan --server-id my-server -- python path/to/target_server.py

# After reviewing a flagged change and confirming it's legitimate, accept it
# as the new baseline instead of getting flagged again next time:
uv run mcp-audit scan --server-id my-server --update-baseline -- python path/to/target_server.py
```

Only tools are fingerprinted today — resources and prompts can drift too in
principle, but tools are MCP's actual invocation surface, so that's where v1
focuses.

## Requirements

- Python 3.11+
- [`mcp`](https://github.com/modelcontextprotocol/python-sdk) — the official
  Python MCP SDK
