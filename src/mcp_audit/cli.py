"""mcp-audit command-line interface.

Exposes two commands:
  - `inspect`: connects to a target MCP server over stdio and prints the
    tools/resources/prompts it exposes (parsing foundation, no checks).
  - `scan`: runs all security checks against a target server and prints a
    report, human-readable (default, via `rich`) or machine-readable
    (`--format json`, for CI/CD gating).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from mcp_audit.checks import ALL_CHECKS, CheckOutcome, Finding, RugPullCheck, compute_default_server_id
from mcp_audit.parser import ServerSnapshot, inspect_server_sync

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]

# Bumped only on a breaking change to the JSON report shape (fields removed,
# renamed, or repurposed). Adding a new field is not breaking and does not
# require a bump. External integrations parsing `scan --format json` should
# key off this to detect a format they don't understand yet, instead of
# breaking silently.
_SCHEMA_VERSION = 1

# Severity -> rich style, per the product's "transparency of coverage" bar:
# critical/high need to read as urgent, medium as a caution, low/info as
# background noise you can skim past.
_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "grey62",
}

_STATUS_STYLE = {
    "ran": "green",
    "skipped": "yellow",
    "not_applicable": "grey62",
}

# Long options that belong to `mcp-audit scan` itself. If one of these shows
# up *inside* the target server's launch command (i.e. after `--`), the user
# almost certainly meant to pass it to mcp-audit and put it in the wrong
# place — Click has no way to reject it (everything after `--` is legally
# the server's argv), so we detect it heuristically and warn instead of
# silently doing nothing. See README "Flag order" section.
_MCPAUDIT_OWN_FLAGS = {"--source-dir", "--server-id", "--update-baseline", "--format"}


def _warn_misplaced_flags(args: list[str]) -> None:
    """Warn if an mcp-audit option was placed after `--` (server-side argv).

    This can't be a hard error: a target server could legitimately accept an
    argument that happens to collide with one of our flag names. So we warn
    loudly on stderr and keep going — the scan still runs (against whatever
    server command the user actually gave us), it just won't have applied
    the option the user probably intended.
    """
    misplaced = sorted({arg.split("=", 1)[0] for arg in args if arg.split("=", 1)[0] in _MCPAUDIT_OWN_FLAGS})
    if not misplaced:
        return

    console = Console(stderr=True)
    flags_str = ", ".join(misplaced)
    console.print(
        f"\n[bold yellow]⚠  Warning:[/bold yellow] {flags_str} appears after "
        "[bold]--[/bold] in your command.",
        highlight=False,
    )
    console.print(
        "   Everything after -- is passed literally to the target server, not to "
        "mcp-audit — so this option was [bold]not applied[/bold].",
        highlight=False,
    )
    console.print(
        "   Put mcp-audit's own options [bold]before[/bold] --, e.g.:\n"
        f"     mcp-audit scan {flags_str} -- <server command>\n",
        highlight=False,
    )


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
    """mcp-audit: security scanner for MCP servers."""


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


def _outcome_to_dict(outcome: CheckOutcome) -> dict:
    return {
        "check_id": outcome.check_id,
        "name": outcome.name,
        "status": outcome.status,
        "reason": outcome.reason,
        "finding_count": len(outcome.findings),
    }


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "severity": finding.severity,
        "check_id": finding.check_id,
        "title": finding.title,
        "description": finding.description,
        "location": finding.location,
    }


def _build_report(
    snapshot: ServerSnapshot,
    server_id: str,
    server_id_was_explicit: bool,
    outcomes: list[CheckOutcome],
) -> dict:
    all_findings = [f for outcome in outcomes for f in outcome.findings]
    summary = {sev: sum(1 for f in all_findings if f.severity == sev) for sev in _SEVERITY_ORDER}
    summary["total"] = len(all_findings)
    gating_count = summary["critical"] + summary["high"]

    return {
        "schema_version": _SCHEMA_VERSION,
        "server": {
            "name": snapshot.server_name,
            "version": snapshot.server_version,
            "protocol_version": snapshot.protocol_version,
            "transport": snapshot.transport,
        },
        "server_id": server_id,
        "server_id_explicit": server_id_was_explicit,
        "checks": [_outcome_to_dict(o) for o in outcomes],
        "findings": [_finding_to_dict(f) for f in all_findings],
        "summary": summary,
        "exit_code": 1 if gating_count else 0,
    }


def _build_error_report(message: str) -> dict:
    """Structured JSON shape for a scan that never got a snapshot to report on.

    Used when the MCP handshake itself fails (target command not found,
    process crashed, protocol/version mismatch, timeout, etc.) — the normal
    report shape assumes a ServerSnapshot exists, which isn't true here.
    """
    return {
        "schema_version": _SCHEMA_VERSION,
        "error": message,
        "exit_code": 1,
    }


def _print_report_json(report: dict) -> None:
    click.echo(json.dumps(report, indent=2))


def _fail_scan(message: str, output_format: str) -> None:
    """Report a scan-ending error (handshake/transport failure, missing
    command, etc.) in the format the user asked for, then exit 1.

    `--format json` is meant to be consumed by CI and other tooling — a
    Python traceback or a plain-text stderr line on the exact same failure
    path is a broken contract for that use case, since a JSON parser fails
    on it too. So an error under `--format json` prints structured JSON on
    stdout (mirroring the shape a successful `_build_report` would use,
    minus fields that require a snapshot we never got) instead of stderr text.
    """
    if output_format == "json":
        click.echo(json.dumps(_build_error_report(message), indent=2))
    else:
        click.echo(f"error: {message}", err=True)
    sys.exit(1)


def _print_report_human(report: dict) -> None:
    console = Console()
    server = report["server"]

    console.print(f"[bold]Server:[/bold] {server['name']} (version {server['version'] or 'unknown'})")
    console.print(f"[bold]Transport:[/bold] {server['transport']}")
    server_id_note = (
        "" if report["server_id_explicit"] else " [grey62](auto-derived from launch command; pass --server-id to pin it)[/grey62]"
    )
    console.print(f"[bold]Server ID[/bold] (rug-pull baseline key): {report['server_id']}{server_id_note}")
    console.print()

    findings = report["findings"]
    if not findings:
        console.print("[bold green]No findings.[/bold green]\n")
    else:
        for severity in _SEVERITY_ORDER:
            sev_findings = [f for f in findings if f["severity"] == severity]
            if not sev_findings:
                continue
            style = _SEVERITY_STYLE[severity]
            console.print(f"[{style}]{severity.upper()} ({len(sev_findings)})[/{style}]")
            for finding in sev_findings:
                console.print(f"  [{style}]• [{finding['check_id']}] {finding['title']}[/{style}]")
                console.print(f"    location: {finding['location']}")
                console.print(f"    {finding['description']}")
            console.print()

    # Coverage table at the end, on purpose: "what did we actually check"
    # is this product's transparency pitch, and it belongs where a reader
    # ends up, not buried above the findings they came here for.
    table = Table(title="Check coverage", show_lines=False)
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    for check in report["checks"]:
        style = _STATUS_STYLE.get(check["status"], "")
        status_label = check["status"].replace("_", " ").upper()
        detail = check["reason"] or ("no findings" if check["finding_count"] == 0 else f"{check['finding_count']} finding(s)")
        table.add_row(f"{check['name']} ({check['check_id']})", f"[{style}]{status_label}[/{style}]", detail)
    console.print(table)

    summary = report["summary"]
    gating = summary["critical"] + summary["high"]
    console.print()
    if gating:
        console.print(
            f"[bold red]FAIL[/bold red]: {gating} critical/high finding(s) "
            f"({summary['critical']} critical, {summary['high']} high)."
        )
    else:
        console.print(
            "[bold green]PASS[/bold green]: no critical/high findings "
            f"({summary['medium']} medium, {summary['low']} low)."
        )


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
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json"]),
    default="human",
    help="Output format. 'json' is structured for CI/CD consumption; 'human' (default) is for terminals.",
)
def scan(
    server_command: tuple[str, ...],
    source_dir: Path | None,
    server_id: str | None,
    update_baseline: bool,
    output_format: str,
) -> None:
    """Connect to a target MCP server, run all security checks, and print a report.

    Pass the command to launch the target server after `--`, e.g.:

        mcp-audit scan -- python examples/toy_server.py

        mcp-audit scan --source-dir examples/ -- python examples/toy_server.py

        mcp-audit scan --server-id my-toy-server -- python examples/toy_server.py

        mcp-audit scan --server-id my-toy-server --update-baseline -- python examples/toy_server.py

    IMPORTANT: mcp-audit's own options (--source-dir, --server-id,
    --update-baseline, --format) must go BEFORE --. Anything after -- is
    passed literally to the target server's argv, including flags that
    happen to share a name with one of ours.

    Exit code is 1 if any critical/high finding was reported (suitable as
    a CI gate), 0 otherwise.
    """
    command_parts = list(server_command)
    if not command_parts:
        click.echo("error: no server command given", err=True)
        sys.exit(1)

    command, *args = command_parts
    _warn_misplaced_flags(args)

    try:
        snapshot = inspect_server_sync(command, args)
    except FileNotFoundError:
        _fail_scan(f"command not found: {command}", output_format)
    except Exception as exc:  # noqa: BLE001 - surface any handshake/transport failure to the user
        _fail_scan(f"failed to inspect server: {exc}", output_format)

    resolved_server_id = server_id or compute_default_server_id(command, args)

    rug_pull_check = RugPullCheck(server_id=resolved_server_id, update_baseline=update_baseline)
    checks_to_run: list = [*ALL_CHECKS, rug_pull_check]

    outcomes: list[CheckOutcome] = [check.run(snapshot, source_dir=source_dir) for check in checks_to_run]
    report = _build_report(snapshot, resolved_server_id, server_id is not None, outcomes)

    if output_format == "json":
        _print_report_json(report)
    else:
        _print_report_human(report)

    sys.exit(report["exit_code"])


if __name__ == "__main__":
    main()
