"""mcp-audit command-line interface.

Currently exposes a single command: `inspect`, which connects to a target
MCP server over stdio and prints the tools/resources/prompts it exposes.
Security checks (tool poisoning, secrets, TLS, etc.) are NOT implemented
yet — this is the parsing foundation they will build on.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from mcp_audit.checks import ALL_CHECKS, CheckOutcome, Finding, RugPullCheck, compute_default_server_id
from mcp_audit.parser import ServerSnapshot, inspect_server_sync

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


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


def _print_outcome(outcome: CheckOutcome) -> None:
    if outcome.status == "ran":
        status_label = "RAN"
    elif outcome.status == "not_applicable":
        status_label = "NOT APPLICABLE"
    else:
        status_label = "SKIPPED"

    click.echo(f"[{status_label}] {outcome.name} ({outcome.check_id})")
    if outcome.reason:
        click.echo(f"    reason: {outcome.reason}")
    if outcome.status == "ran" and not outcome.findings:
        click.echo("    no findings")


def _print_findings_by_severity(findings: list[Finding]) -> None:
    by_severity: dict[str, list[Finding]] = {sev: [] for sev in _SEVERITY_ORDER}
    for finding in findings:
        by_severity.setdefault(finding.severity, []).append(finding)

    if not findings:
        click.echo("No findings.")
        return

    for severity in _SEVERITY_ORDER:
        sev_findings = by_severity.get(severity, [])
        if not sev_findings:
            continue
        click.echo(f"\n{severity.upper()} ({len(sev_findings)}):")
        for finding in sev_findings:
            click.echo(f"  - [{finding.check_id}] {finding.title}")
            click.echo(f"    location: {finding.location}")
            click.echo(f"    {finding.description}")


@main.command()
@click.argument("server_command", nargs=-1, required=True)
@click.option(
    "--source-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to the target server's source code, to enable the hardcoded-secrets check.",
)
@click.option(
    "--server-id",
    default=None,
    help=(
        "Stable identifier for this server, used as the rug-pull baseline key. "
        "Defaults to a hash of the launch command if omitted — pass an explicit "
        "value if you expect the command/args to change across runs of the same server."
    ),
)
@click.option(
    "--update-baseline",
    is_flag=True,
    default=False,
    help=(
        "Overwrite the stored rug-pull baseline with this run's snapshot instead "
        "of comparing against it. Use after confirming a detected change is legitimate."
    ),
)
def scan(
    server_command: tuple[str, ...],
    source_dir: Path | None,
    server_id: str | None,
    update_baseline: bool,
) -> None:
    """Connect to a target MCP server, run all security checks, and print a report.

    Pass the command to launch the target server after `--`, e.g.:

        mcp-audit scan -- python examples/toy_server.py

        mcp-audit scan --source-dir examples/ -- python examples/toy_server.py

        mcp-audit scan --server-id my-toy-server -- python examples/toy_server.py

        mcp-audit scan --server-id my-toy-server --update-baseline -- python examples/toy_server.py
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

    resolved_server_id = server_id or compute_default_server_id(command, args)

    click.echo(f"Server: {snapshot.server_name} (version {snapshot.server_version or 'unknown'})")
    click.echo(f"Transport: {snapshot.transport}")
    click.echo(
        f"Server ID (rug-pull baseline key): {resolved_server_id}"
        + ("" if server_id else " (auto-derived from launch command; pass --server-id to pin it)")
    )
    click.echo()

    rug_pull_check = RugPullCheck(server_id=resolved_server_id, update_baseline=update_baseline)
    checks_to_run: list = [*ALL_CHECKS, rug_pull_check]

    click.echo("Checks:")
    all_findings: list[Finding] = []
    for check in checks_to_run:
        outcome = check.run(snapshot, source_dir=source_dir)
        _print_outcome(outcome)
        all_findings.extend(outcome.findings)
    click.echo()

    click.echo("Findings:")
    _print_findings_by_severity(all_findings)

    critical_count = sum(1 for f in all_findings if f.severity == "critical")
    if critical_count:
        sys.exit(1)


if __name__ == "__main__":
    main()
