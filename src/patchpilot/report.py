"""Render an Outcome as a merge-request comment and as JSON."""
from __future__ import annotations

import json
from typing import Any

from .pipeline import Outcome

_BADGE = {"critical": "🟥", "high": "🟧", "moderate": "🟨", "medium": "🟨", "low": "🟦", "info": "⬜"}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_markdown(outcome: Outcome) -> str:
    total = len(outcome.fixed) + len(outcome.routed)
    lines = [
        "### PatchPilot security report",
        "",
        f"**{len(outcome.fixed)} of {total}** findings fixed automatically; "
        f"**{len(outcome.routed)}** need an engineer.",
        "",
    ]
    if outcome.fixed:
        lines += ["#### Fixed", "", "| Severity | Finding | Where | Change |", "|---|---|---|---|"]
        for r in outcome.fixed:
            f = r.finding
            lines.append(f"| {_BADGE.get(f.severity, '')} {f.severity} | {_cell(f.title)} | `{f.location()}` | {_cell(r.summary)} |")
        lines.append("")
    if outcome.routed:
        lines += ["#### Needs an engineer", ""]
        for r in outcome.routed:
            f = r.finding
            lines.append(f"- {_BADGE.get(f.severity, '')} **{f.severity}** · {f.title} · `{f.location()}`")
            lines.append(f"  - Why it was not auto-fixed: {r.summary}")
            if r.suggestion:
                body = "\n".join("    " + line for line in r.suggestion.splitlines())
                lines.append("  - Suggested fix:\n" + body)
        lines.append("")
    return "\n".join(lines)


def to_json(outcome: Outcome) -> str:
    def row(r: Any) -> dict[str, Any]:
        return {
            "finding": r.finding.to_dict(),
            "applied": r.applied,
            "fixer": r.fixer,
            "summary": r.summary,
            "suggestion": r.suggestion,
        }

    return json.dumps({"fixed": [row(r) for r in outcome.fixed], "routed": [row(r) for r in outcome.routed]}, indent=2)
