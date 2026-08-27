"""Unit tests for CrossToolShadowingCheck.

Pure unit tests: ToolInfo/ServerSnapshot objects are built synthetically.
Covers both detection modes documented in `cross_tool_shadowing.py`'s
module docstring:
  - similarity against the curated reference list (official filesystem /
    git / fetch / memory MCP servers)
  - similarity between two tools exposed by the same server

...plus the honesty cases: an exact match against a reference name is NOT
a finding (that's just correctly implementing the well-known tool), and
`examples/toy_server.py`-style tool names stay clean.
"""

from __future__ import annotations

from mcp_audit.checks.cross_tool_shadowing import CrossToolShadowingCheck
from mcp_audit.parser import ServerSnapshot, ToolInfo


def _snapshot_with_tools(*names: str) -> ServerSnapshot:
    return ServerSnapshot(
        server_name="test-server",
        server_version="0.1.0",
        protocol_version="2025-06-18",
        tools=[ToolInfo(name=name, description=f"Does something with {name}.") for name in names],
    )


def test_toy_server_style_tools_produce_no_findings() -> None:
    # Same tool names as examples/toy_server.py — none close to a reference
    # name or to each other.
    snapshot = _snapshot_with_tools("add", "get_weather", "reverse_text")

    outcome = CrossToolShadowingCheck().run(snapshot)

    assert outcome.status == "ran"
    assert outcome.findings == []


def test_exact_match_against_reference_name_is_not_flagged() -> None:
    # Implementing "read_file" exactly like the official filesystem server
    # is the normal, expected thing to do — not shadowing.
    snapshot = _snapshot_with_tools("read_file")

    outcome = CrossToolShadowingCheck().run(snapshot)

    assert outcome.findings == []


def test_typo_variant_of_reference_name_is_flagged() -> None:
    # Single-character substitution, mirrors the read_file -> read_flle
    # example from the task brief.
    snapshot = _snapshot_with_tools("read_flle")

    outcome = CrossToolShadowingCheck().run(snapshot)

    matches = [f for f in outcome.findings if f.location == "tool:read_flle"]
    assert matches
    assert matches[0].severity == "medium"
    assert "read_file" in matches[0].description


def test_missing_character_variant_of_reference_name_is_flagged() -> None:
    # Single-character deletion, mirrors list_directory -> list_directoy.
    snapshot = _snapshot_with_tools("list_directoy")

    outcome = CrossToolShadowingCheck().run(snapshot)

    matches = [f for f in outcome.findings if f.location == "tool:list_directoy"]
    assert matches
    assert "list_directory" in matches[0].description


def test_separator_only_difference_is_flagged_as_normalized_collision() -> None:
    # "readfile" normalizes identically to "read_file" despite a small raw
    # edit distance from stripping the separator.
    snapshot = _snapshot_with_tools("readfile")

    outcome = CrossToolShadowingCheck().run(snapshot)

    matches = [f for f in outcome.findings if f.location == "tool:readfile"]
    assert matches
    assert "normalizes to the exact same name" in matches[0].description


def test_unrelated_short_name_is_not_flagged_against_reference_list() -> None:
    # "fetch" is a real reference name; an unrelated short tool shouldn't
    # coincidentally collide with it or anything else in the list.
    snapshot = _snapshot_with_tools("sum")

    outcome = CrossToolShadowingCheck().run(snapshot)

    assert outcome.findings == []


def test_two_similar_tool_names_on_same_server_are_flagged() -> None:
    snapshot = _snapshot_with_tools("list_files", "list_filez")

    outcome = CrossToolShadowingCheck().run(snapshot)

    matches = [f for f in outcome.findings if "on this server have suspiciously similar names" in f.title]
    assert matches
    assert matches[0].severity == "medium"


def test_two_unrelated_tool_names_on_same_server_are_not_flagged() -> None:
    snapshot = _snapshot_with_tools("add", "get_weather")

    outcome = CrossToolShadowingCheck().run(snapshot)

    assert outcome.findings == []


def test_status_is_always_ran() -> None:
    outcome = CrossToolShadowingCheck().run(_snapshot_with_tools("add"))

    assert outcome.status == "ran"
    assert outcome.check_id == "cross-tool-shadowing"
    assert "add" not in (outcome.reason or "")  # reason is a summary, not per-tool detail
