"""Check: Unicode tag-block / invisible-character concealment in metadata.

Background (see Rashidi, "Unicode TAG-Block Concealment of Tool-Metadata
Payloads in the Model Context Protocol", arXiv:2607.05744, Jul 2026):

MCP clients render a tool's `description` once, in a human approval
dialog, then forward the *same bytes* to the model on every subsequent
turn. Nothing in the protocol requires the human-facing render and the
model-facing bytes to match. The paper isolates this "approval-view
fidelity gap" and shows that encoding a payload in the Unicode TAG block
(U+E0000-U+E007F) defeats it completely: the block was defined for
language tagging, is deprecated, and has no assigned glyph in any
mainstream terminal/chat/IDE renderer, so a human reviewing the tool sees
nothing unusual — but a model's tokenizer decodes and consumes the bytes
like any other valid Unicode, because tokenizers have no "does this have
a glyph" precondition the way renderers do.

The paper's reference encoder (`tag_encode`) maps each ASCII byte of a
hidden instruction to a TAG codepoint via:

    chr(0xE0000 + (ord(c) & 0x7F))

which is directly invertible for the ASCII range: subtract 0xE0000 from
each TAG codepoint to recover the original byte.

This check does two things:
  1. Scans for TAG-block codepoints specifically (the paper's headline
     technique, which is the only one of its 8 tested techniques that
     evades *both* a string-matching sanitizer and human review) and
     attempts to decode any contiguous run back to ASCII.
  2. Scans for other invisible/format characters that have no legitimate
     reason to appear in a tool/resource/prompt description (zero-width
     spaces/joiners, bidi override controls, BOM, word joiner, etc.) —
     these don't have the paper's clean 7-bit decode, but their presence
     in metadata that a human is meant to read and approve is itself a
     red flag worth surfacing.

Both categories are reported as "critical": per the paper's own findings,
a defense that only catches the overt, plain-ASCII injection attempts
(T1/T2 in their taxonomy) while missing concealment encoding (T7) has
already lost the one case that matters, so there's no honest "medium"
severity to assign to "we found characters whose only purpose is to hide
from you."
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp_audit.checks.base import Check, CheckOutcome, Finding
from mcp_audit.parser import ServerSnapshot

CHECK_ID = "unicode-concealment"

TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

# Characters with no legitimate reason to appear in natural-language tool
# metadata that a human is meant to read. This is a deliberately narrow,
# named list (rather than "any Cf category codepoint") because a couple
# of Cf characters (ZWJ/ZWNJ) have legitimate uses in some scripts and
# emoji sequences; we still flag them here since an MCP tool description
# is English/ASCII-oriented product copy, not user-authored script text,
# so their presence is still suspicious in this context — just labeled
# for what it is rather than lumped in with the TAG-block technique.
_SUSPICIOUS_INVISIBLE_CHARS: dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE / BOM",
    "­": "SOFT HYPHEN",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "‪": "LEFT-TO-RIGHT EMBEDDING (bidi override)",
    "‫": "RIGHT-TO-LEFT EMBEDDING (bidi override)",
    "‬": "POP DIRECTIONAL FORMATTING (bidi override)",
    "‭": "LEFT-TO-RIGHT OVERRIDE (bidi override)",
    "‮": "RIGHT-TO-LEFT OVERRIDE (bidi override)",
    "⁦": "LEFT-TO-RIGHT ISOLATE (bidi override)",
    "⁧": "RIGHT-TO-LEFT ISOLATE (bidi override)",
    "⁨": "FIRST STRONG ISOLATE (bidi override)",
    "⁩": "POP DIRECTIONAL ISOLATE (bidi override)",
}


@dataclass
class _NamedText:
    kind: str  # "tool" | "resource" | "prompt"
    name: str
    text: str


def _is_tag_char(ch: str) -> bool:
    return TAG_BLOCK_START <= ord(ch) <= TAG_BLOCK_END


def _decode_tag_run(run: str) -> str | None:
    """Invert the paper's tag_encode: chr(0xE0000 + (ord(c) & 0x7F)).

    Returns the best-effort decoded text, or None if the run decodes to
    nothing printable at all.
    """
    raw_bytes = bytes((ord(ch) - TAG_BLOCK_START) & 0xFF for ch in run)
    try:
        decoded = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        decoded = raw_bytes.decode("latin-1", errors="replace")

    if any(ch.isprintable() for ch in decoded):
        return decoded
    return None


def _find_tag_runs(text: str) -> list[str]:
    runs: list[str] = []
    current = ""
    for ch in text:
        if _is_tag_char(ch):
            current += ch
        else:
            if current:
                runs.append(current)
            current = ""
    if current:
        runs.append(current)
    return runs


def _iter_texts(snapshot: ServerSnapshot):
    for tool in snapshot.tools:
        if tool.description:
            yield _NamedText("tool", tool.name, tool.description)
    for resource in snapshot.resources:
        if resource.description:
            yield _NamedText("resource", resource.name or resource.uri, resource.description)
    for prompt in snapshot.prompts:
        if prompt.description:
            yield _NamedText("prompt", prompt.name, prompt.description)


class UnicodeConcealmentCheck(Check):
    check_id = CHECK_ID
    name = "Unicode tag-block / invisible-character concealment"

    def run(self, snapshot: ServerSnapshot, source_dir: Path | None = None) -> CheckOutcome:
        findings: list[Finding] = []

        for item in _iter_texts(snapshot):
            location = f"{item.kind}:{item.name}"

            tag_runs = _find_tag_runs(item.text)
            for run in tag_runs:
                decoded = _decode_tag_run(run)
                if decoded is not None:
                    description = (
                        f"Found {len(run)} character(s) in the Unicode TAG block "
                        f"(U+E0000-U+E007F) hidden inside this {item.kind}'s description. "
                        "This block has no assigned glyph in any mainstream renderer, so a "
                        "human approving this tool sees nothing, while an LLM's tokenizer "
                        "decodes it like ordinary text. Decoded payload: "
                        f"{decoded!r}"
                    )
                else:
                    description = (
                        f"Found {len(run)} character(s) in the Unicode TAG block "
                        f"(U+E0000-U+E007F) hidden inside this {item.kind}'s description. "
                        "Could not decode a printable payload from this run, but the "
                        "block's mere presence in human-facing metadata is itself a "
                        "concealment attempt (see arXiv:2607.05744)."
                    )
                findings.append(
                    Finding(
                        severity="critical",
                        check_id=self.check_id,
                        title=f"Hidden Unicode TAG-block payload in {item.kind} description",
                        description=description,
                        location=location,
                    )
                )

            found_invisible: dict[str, int] = {}
            for ch in item.text:
                if ch in _SUSPICIOUS_INVISIBLE_CHARS:
                    found_invisible[ch] = found_invisible.get(ch, 0) + 1

            for ch, count in found_invisible.items():
                char_name = _SUSPICIOUS_INVISIBLE_CHARS[ch]
                codepoint = f"U+{ord(ch):04X}"
                findings.append(
                    Finding(
                        severity="critical",
                        check_id=self.check_id,
                        title=f"Suspicious invisible character in {item.kind} description",
                        description=(
                            f"Found {count} occurrence(s) of {char_name} ({codepoint}) in this "
                            f"{item.kind}'s description. This character renders invisibly (or "
                            "alters bidi text direction) and has no legitimate reason to appear "
                            "in plain English tool metadata; it may be used to conceal or "
                            "reorder an injected instruction."
                        ),
                        location=location,
                    )
                )

        return CheckOutcome(
            check_id=self.check_id,
            name=self.name,
            status="ran",
            findings=findings,
        )
