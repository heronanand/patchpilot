"""LLM-drafted fixes for code findings that have no deterministic fix.

The model sees only a window of the flagged file and must answer in JSON.
Drafts are attached to the report for an engineer by default; they are
written to disk only with --apply-llm, and only when the model reports
high confidence and the test command still passes.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .findings import Finding

DEFAULT_MODEL = os.environ.get("PATCHPILOT_MODEL", "claude-sonnet-5-5")
CONTEXT_LINES = 8

SYSTEM_PROMPT = """You fix one security finding in source code.
Return ONLY a JSON object with these keys:
  "replacement": the new text for the flagged lines (the exact line range given), keeping indentation,
  "explanation": one or two sentences an engineer can review quickly,
  "confidence": "high" if the fix is minimal, behaviour-preserving and certainly closes the issue; otherwise "medium" or "low".
Change only the flagged lines. Do not add imports outside the range; if one is needed, set confidence to "medium" and say so."""


class Completion(Protocol):
    def __call__(self, system: str, prompt: str) -> str: ...


@dataclass
class Draft:
    replacement: str
    explanation: str
    confidence: str

    @property
    def safe_to_apply(self) -> bool:
        return self.confidence == "high"


def anthropic_completion(model: str = DEFAULT_MODEL) -> Completion:
    """Build a completion function backed by the Anthropic API."""
    import anthropic  # imported lazily so the rest of the tool works without it

    client = anthropic.Anthropic()

    def complete(system: str, prompt: str) -> str:
        message = client.messages.create(
            model=model,
            max_tokens=1200,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in message.content if getattr(block, "type", "") == "text")

    return complete


def build_prompt(finding: Finding, source: str) -> str:
    lines = source.splitlines()
    start, end = finding.start_line or 1, finding.end_line or finding.start_line or 1
    lo, hi = max(1, start - CONTEXT_LINES), min(len(lines), end + CONTEXT_LINES)
    numbered = "\n".join(f"{n:>5} | {lines[n - 1]}" for n in range(lo, hi + 1))
    return (
        f"Finding: {finding.title}\n"
        f"Rule: {finding.rule}\nSeverity: {finding.severity}\n"
        f"File: {finding.path}\nFlagged lines: {start}-{end}\n\n"
        f"Context (line numbers are not part of the file):\n{numbered}\n"
    )


def parse_draft(text: str) -> Draft:
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        raise ValueError("Model did not return JSON.")
    data = json.loads(match.group())
    confidence = str(data.get("confidence", "low")).lower()
    if confidence not in {"high", "medium", "low"}:
        confidence = "low"
    return Draft(
        replacement=str(data["replacement"]).rstrip("\n"),
        explanation=str(data.get("explanation", "")).strip(),
        confidence=confidence,
    )


def draft_fix(finding: Finding, repo: Path, complete: Completion) -> Draft:
    source = (repo / (finding.path or "")).read_text(encoding="utf-8")
    return parse_draft(complete(SYSTEM_PROMPT, build_prompt(finding, source)))


def apply_draft(finding: Finding, repo: Path, draft: Draft) -> str:
    """Replace the flagged lines with the draft. Returns the original file text."""
    target = repo / (finding.path or "")
    original = target.read_text(encoding="utf-8")
    lines = original.splitlines(keepends=True)
    start, end = (finding.start_line or 1) - 1, finding.end_line or finding.start_line or 1
    ending = "\n" if lines[end - 1].endswith("\n") else ""
    lines[start:end] = [draft.replacement + ending]
    target.write_text("".join(lines), encoding="utf-8")
    return original
