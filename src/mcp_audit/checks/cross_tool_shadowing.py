"""Check: cross-tool shadowing / tool-name confusion.

Background — confirmed via research before writing this, not assumed
--------------------------------------------------------------------
"Tool shadowing" is a documented MCP attack class (SAFE-MCP's technique
catalog lists it as SAF-T1301 "Cross-Server Tool Shadowing", tactic
Privilege Escalation; see also Damn Vulnerable MCP Server's own Challenge 5
of the same name, and Akto's MCP Attack Matrix entry). Its own definition
covers more ground than a single mechanism:

    "Cross-Server Tool Shadowing is a privilege escalation technique where
    malicious MCP servers override or intercept legitimate tool calls from
    other servers to gain elevated privileges. This attack exploits the
    multi-server nature of MCP environments where multiple servers can
    provide tools with the same or similar names..."

The catalog explicitly lists both **identical-name collisions** and
**similar-name attacks** ("using tool names with subtle differences, e.g.
'file_manager' vs 'file-manager'") plus Unicode-confusable names as
distinct attack vectors under the same technique. A real agent session
commonly has multiple MCP servers connected at once (e.g. a filesystem
server, a git server, a fetch server) — a newly-added server offering a
tool that reads as "the same" as one already trusted primes the agent to
misuse it, whether by exact collision or by the human/agent conflating two
near-identical names during approval.

What this check can and can't see
----------------------------------
`mcp-audit` inspects **one MCP server per invocation** (a single stdio
subprocess) — it has no visibility into whatever *other* servers might be
connected in the same live agent session, so it cannot literally detect
"this collides with the other server the user also has open" the way a
client-side proxy could. Two things it *can* do without that visibility:

1. **Compare against a curated reference list** of tool names from the
   official MCP reference servers (`filesystem`, `git`, `fetch`, `memory`
   — the servers namechecked in this project's own README as "servers we
   already know") as a stand-in for "a tool name an agent is likely to
   already trust from a real multi-server session". A tool on the
   *current* server whose name is suspiciously close to one of these,
   without being identical, is exactly the "similar name" vector from the
   technique catalog above.
2. **Compare tool names against each other within the same server.** Two
   tools on the *same* server with near-identical names is the
   "decoy"/"namespace pollution" pattern from the same catalog — one may
   exist purely so a careless approval or a confused agent picks the wrong
   one.

Similarity is Levenshtein (edit) distance, scaled to name length so short
names aren't flooded with matches and long names still catch a
single-character typo-style substitution
(`read_file` -> `read_flle`, `list_directory` -> `list_directoy`). Two
names are also flagged, regardless of raw distance, if they become
identical after stripping separators/case (`read_file` vs `readfile`) —
that pair looks the same to a skimming human but is a distinct literal
tool name to the protocol and to any code keying off `tool.name`.

An exact match against a reference name is **not** flagged — a server that
implements `read_file` exactly like the official filesystem server's
`read_file` is doing the normal, expected thing; there's nothing
shadow-like about correctly naming a tool after what it does. The
interesting case is *near* but not identical.

Honesty about confidence — heuristic, both directions
-------------------------------------------------------
- **False positives**: legitimate, unrelated tools can land within a small
  edit distance purely by coincidence, especially for short names
  (`add`/`sub`, `get`/`set`). Deliberate near-duplicates also have entirely
  benign explanations — API versioning (`get_user` / `get_user_v2`),
  singular/plural pairs (`list_file` / `list_files`), or a server that
  genuinely re-implements a well-known tool under a near-identical name for
  compatibility reasons. Every finding says this explicitly.
- **False negatives**: this only catches *lexical* closeness. A server
  intentionally shadowing a trusted tool by choosing an outright unrelated
  name (no textual resemblance) is invisible to this check by definition —
  see the "sensitive-path co-occurrence" and "instruction-wrapper" checks
  in `tool_poisoning.py` for a different signal on that. Homoglyph attacks
  using visually-identical but codepoint-different characters (Cyrillic
  vs. Latin `a`) *are* often caught incidentally, since substituting one
  character is a Levenshtein distance of exactly 1 — but a name using
  several homoglyphs at once could exceed the distance threshold and slip
  through. And the reference list itself is a fixed, small snapshot of a
  handful of official servers as of when this check was written — it will
  drift out of date as those servers add tools, and says nothing about the
  thousands of third-party servers a real session might also have
  connected.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp_audit.checks.base import Check, CheckOutcome, Finding
from mcp_audit.parser import ServerSnapshot

CHECK_ID = "cross-tool-shadowing"

# Tool names from the official MCP reference servers
# (github.com/modelcontextprotocol/servers), the same ones this project's
# own README already demos mcp-audit against. Used as a stand-in for "a
# tool name an agent is likely to already trust" from a real multi-server
# session mcp-audit can't directly observe (see module docstring).
_REFERENCE_TOOL_NAMES: dict[str, str] = {
    # filesystem
    "read_file": "filesystem",
    "read_multiple_files": "filesystem",
    "write_file": "filesystem",
    "edit_file": "filesystem",
    "create_directory": "filesystem",
    "list_directory": "filesystem",
    "list_directory_with_sizes": "filesystem",
    "directory_tree": "filesystem",
    "move_file": "filesystem",
    "search_files": "filesystem",
    "get_file_info": "filesystem",
    "list_allowed_directories": "filesystem",
    # git
    "git_status": "git",
    "git_diff_unstaged": "git",
    "git_diff_staged": "git",
    "git_diff": "git",
    "git_commit": "git",
    "git_add": "git",
    "git_reset": "git",
    "git_log": "git",
    "git_create_branch": "git",
    "git_checkout": "git",
    "git_show": "git",
    "git_init": "git",
    # fetch
    "fetch": "fetch",
    # memory
    "create_entities": "memory",
    "create_relations": "memory",
    "add_observations": "memory",
    "delete_entities": "memory",
    "delete_observations": "memory",
    "delete_relations": "memory",
    "read_graph": "memory",
    "search_nodes": "memory",
    "open_nodes": "memory",
}


def _levenshtein(a: str, b: str) -> int:
    """Classic iterative edit-distance DP, O(len(a) * len(b)) time, O(len(b)) space.

    No third-party fuzzy-matching dependency needed for a same-magnitude
    algorithm this small — consistent with the project's minimal-dependency
    footprint (see pyproject.toml).
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            replace_cost = previous_row[j - 1] + (0 if ca == cb else 1)
            current_row[j] = min(insert_cost, delete_cost, replace_cost)
        previous_row = current_row
    return previous_row[-1]


def _normalize(name: str) -> str:
    return name.lower().replace("_", "").replace("-", "").replace(" ", "")


def _max_allowed_distance(name_len: int) -> int:
    """Scale the "suspiciously close" threshold to name length, so a short
    name isn't flooded with coincidental matches (e.g. "get"/"set" would be
    distance 1 on a 3-char name) while a longer name can still catch a
    single-character-swap or single-character-drop typo."""
    if name_len <= 5:
        return 1
    if name_len <= 12:
        return 2
    return 3


@dataclass
class _SimilarPair:
    distance: int
    normalized_collision: bool


def _compare_names(name_a: str, name_b: str) -> _SimilarPair | None:
    if name_a == name_b:
        return None

    normalized_a, normalized_b = _normalize(name_a), _normalize(name_b)
    normalized_collision = normalized_a == normalized_b and normalized_a != ""

    distance = _levenshtein(name_a.lower(), name_b.lower())
    threshold = _max_allowed_distance(max(len(name_a), len(name_b)))

    if normalized_collision or (0 < distance <= threshold):
        return _SimilarPair(distance=distance, normalized_collision=normalized_collision)
    return None


def _check_against_reference(tool_name: str) -> list[Finding]:
    findings: list[Finding] = []
    for reference_name, server_family in _REFERENCE_TOOL_NAMES.items():
        pair = _compare_names(tool_name, reference_name)
        if pair is None:
            continue
        collision_note = (
            "differs only by separators/case, so it normalizes to the exact same name"
            if pair.normalized_collision
            else f"Levenshtein distance {pair.distance}"
        )
        findings.append(
            Finding(
                severity="medium",
                check_id=CHECK_ID,
                title=f"Tool '{tool_name}' has a suspiciously similar name to well-known tool '{reference_name}'",
                description=(
                    f"Tool '{tool_name}' is not identical to, but is close to ({collision_note}), "
                    f"'{reference_name}' — a tool name from the official {server_family} MCP "
                    "reference server that an agent connected to multiple servers may already "
                    "trust. This is the 'similar name' vector of cross-tool shadowing/name "
                    "squatting: an agent (or a human skimming a tool-approval list) can mistake "
                    "one for the other. Heuristic, string-similarity only — see "
                    "checks/cross_tool_shadowing.py's module docstring for real false-positive "
                    "cases (API versioning, singular/plural pairs) this can't distinguish from "
                    "an actual squatting attempt."
                ),
                location=f"tool:{tool_name}",
            )
        )
    return findings


def _check_within_server(tool_names: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen_pairs: set[tuple[str, str]] = set()
    for i, name_a in enumerate(tool_names):
        for name_b in tool_names[i + 1 :]:
            first, second = sorted((name_a, name_b))
            pair_key = (first, second)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            pair = _compare_names(name_a, name_b)
            if pair is None:
                continue
            collision_note = (
                "differ only by separators/case, so they normalize to the exact same name"
                if pair.normalized_collision
                else f"Levenshtein distance {pair.distance}"
            )
            findings.append(
                Finding(
                    severity="medium",
                    check_id=CHECK_ID,
                    title=f"Tools '{name_a}' and '{name_b}' on this server have suspiciously similar names",
                    description=(
                        f"This server exposes both '{name_a}' and '{name_b}' ({collision_note}). "
                        "Two near-identical tool names on the same server is the "
                        "'decoy'/namespace-pollution pattern of cross-tool shadowing: one may "
                        "exist to get invoked by mistake instead of the other, whether by a "
                        "confused agent or a human approving too quickly. Heuristic, "
                        "string-similarity only — legitimate explanations exist (API versioning, "
                        "singular/plural pairs); worth a human look, not proof of malicious "
                        "intent."
                    ),
                    location=f"tool:{name_a}",
                )
            )
    return findings


class CrossToolShadowingCheck(Check):
    check_id = CHECK_ID
    name = "Cross-tool shadowing / tool-name confusion"

    def run(self, snapshot: ServerSnapshot, source_dir: Path | None = None) -> CheckOutcome:
        tool_names = [tool.name for tool in snapshot.tools]

        findings: list[Finding] = []
        for tool_name in tool_names:
            findings.extend(_check_against_reference(tool_name))
        findings.extend(_check_within_server(tool_names))

        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            reason=(
                f"compared {len(tool_names)} tool name(s) against a curated list of "
                f"{len(_REFERENCE_TOOL_NAMES)} well-known tool names from the official MCP "
                "filesystem/git/fetch/memory reference servers, and against each other, for "
                "suspiciously similar (but not identical) names. mcp-audit inspects one server "
                "per invocation and cannot see other servers connected in the same live agent "
                "session — see module docstring for what this approximates and what it can't."
            ),
            findings=findings,
        )
