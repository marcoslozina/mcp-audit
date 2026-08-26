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

## Requirements

- Python 3.11+
- [`mcp`](https://github.com/modelcontextprotocol/python-sdk) — the official
  Python MCP SDK
