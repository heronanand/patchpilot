"""Run every finding through fix -> verify -> route."""
from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding, severity_rank
from .fixers import FixResult, rollback, routine_fix
from .llm import Completion, apply_draft, draft_fix


@dataclass
class Outcome:
    fixed: list[FixResult] = field(default_factory=list)
    routed: list[FixResult] = field(default_factory=list)

    def worst_routed(self) -> str | None:
        if not self.routed:
            return None
        return max((r.finding.severity for r in self.routed), key=severity_rank)


@dataclass
class Options:
    repo: Path
    test_cmd: str | None = None
    llm: Completion | None = None
    apply_llm: bool = False
    dry_run: bool = False


def run_tests(cmd: str, repo: Path) -> tuple[bool, str]:
    proc = subprocess.run(shlex.split(cmd), cwd=repo, capture_output=True, text=True, timeout=900)
    tail = (proc.stdout + proc.stderr).strip().splitlines()[-15:]
    return proc.returncode == 0, "\n".join(tail)


def _verify_or_rollback(result: FixResult, opts: Options) -> FixResult:
    if not result.applied or not opts.test_cmd:
        return result
    ok, log = run_tests(opts.test_cmd, opts.repo)
    if ok:
        result.summary += " Tests pass."
        return result
    rollback(result)
    result.applied = False
    result.summary = f"Reverted: tests failed after the change ({result.summary})"
    result.suggestion = log
    return result


def process(findings: list[Finding], opts: Options) -> Outcome:
    outcome = Outcome()
    for finding in findings:
        result = routine_fix(finding, opts.repo)
        if result.applied and opts.dry_run:
            rollback(result)
            result.summary = "[dry run] " + result.summary
        else:
            result = _verify_or_rollback(result, opts)

        if not result.applied and finding.kind == "code" and opts.llm is not None and not opts.dry_run:
            result = _try_llm(finding, opts, routine_reason=result.summary)

        (outcome.fixed if result.applied or result.summary.startswith("[dry run]") else outcome.routed).append(result)
    return outcome


def _try_llm(finding: Finding, opts: Options, routine_reason: str) -> FixResult:
    try:
        draft = draft_fix(finding, opts.repo, opts.llm)
    except Exception as exc:  # network, quota, bad JSON: never crash the pipeline
        return FixResult(finding, False, f"{routine_reason} LLM draft failed: {exc}", fixer="llm")

    suggestion = f"{draft.explanation}\n\n```\n{draft.replacement}\n```"
    if not (opts.apply_llm and draft.safe_to_apply):
        reason = "LLM draft attached for review" + ("" if draft.safe_to_apply else f" (model confidence: {draft.confidence})")
        return FixResult(finding, False, f"{routine_reason} {reason}.", suggestion=suggestion, fixer="llm")

    original = apply_draft(finding, opts.repo, draft)
    result = FixResult(
        finding,
        True,
        f"Applied an LLM fix at {finding.location()}: {draft.explanation}",
        files={str(opts.repo / (finding.path or "")): original},
        suggestion=suggestion,
        fixer="llm",
    )
    return _verify_or_rollback(result, opts)
