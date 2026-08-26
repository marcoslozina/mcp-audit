"""mcp-audit command-line interface.

Currently exposes a single command: `inspect`, which connects to a target
MCP server over stdio and prints the tools/resources/prompts it exposes.
Security checks (tool poisoning, secrets, TLS, etc.) are NOT implemented
yet — this is the parsing foundation they will build on.
"""

from __future__ import annotations

import sys

import click

from mcp_audit.parser import ServerSnapshot, inspect_server_sync


def _print_snapshot(snapshot: ServerSnapshot) -> None:
    click.echo(f"Server: {snapshot.server_name} (version {snapshot.server_version or 'unknown'})")
    click.echo(f"Protocol version: {snapshot.protocol_version}")
    click.echo()

    click.echo(f"Tools ({len(snapshot.tools)}):")
    if not snapshot.tools:
        click.echo("  (none)")
    for tool in snapshot.tools:
        click.echo(f"  - {tool.name}: {tool.description or '(no description)'}")
        properties = (tool.input_schema or {}).get("properties", {})
        if properties:
            for param_name, param_schema in properties.items():
                param_type = param_schema.get("type", "any")
                click.echo(f"      {param_name}: {param_type}")
    click.echo()

    click.echo(f"Resources ({len(snapshot.resources)}):")
    if not snapshot.resources:
        click.echo("  (none)")
    for resource in snapshot.resources:
        click.echo(f"  - {resource.uri}: {resource.description or resource.name or '(no description)'}")
    click.echo()

    click.echo(f"Prompts ({len(snapshot.prompts)}):")
    if not snapshot.prompts:
        click.echo("  (none)")
    for prompt in snapshot.prompts:
        click.echo(f"  - {prompt.name}: {prompt.description or '(no description)'}")


@click.group()
@click.version_option()
def main() -> None:
    """mcp-audit: security scanner for MCP servers (early MVP — parsing foundation only)."""


@main.command()
@click.argument("server_command", nargs=-1, required=True)
def inspect(server_command: tuple[str, ...]) -> None:
    """Connect to a target MCP server over stdio and print its tools/resources/prompts.

    Pass the command to launch the target server after `--`, e.g.:

        mcp-audit inspect -- python examples/toy_server.py
    """
    command_parts = list(server_command)
    if not command_parts:
        click.echo("error: no server command given", err=True)
        sys.exit(1)

    command, *args = command_parts

    try:
        snapshot = inspect_server_sync(command, args)
    except FileNotFoundError:
        click.echo(f"error: command not found: {command}", err=True)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 - surface any handshake/transport failure to the user
        click.echo(f"error: failed to inspect server: {exc}", err=True)
        sys.exit(1)

    _print_snapshot(snapshot)


if __name__ == "__main__":
    main()
