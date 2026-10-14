"""Command-line entry point: `patchpilot --repo . --semgrep semgrep.json ...`"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .findings import SEVERITY_ORDER, load_reports, severity_rank
from .pipeline import Options, process
from .report import to_json, to_markdown


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="patchpilot",
        description="Turn security-scan findings into fixes: routine ones are applied and tested, the rest are routed to an engineer with a drafted fix.",
    )
    p.add_argument("--repo", type=Path, default=Path("."), help="Repository root (default: current directory)")
    p.add_argument("--npm-audit", type=Path, help="Output of `npm audit --json`")
    p.add_argument("--pip-audit", type=Path, help="Output of `pip-audit -f json`")
    p.add_argument("--semgrep", type=Path, help="Output of `semgrep --json`")
    p.add_argument("--test-cmd", help="Command that must still pass after each fix, e.g. \"pytest -q\"")
    p.add_argument("--llm", action="store_true", help="Draft fixes for code findings with Claude (needs ANTHROPIC_API_KEY)")
    p.add_argument("--apply-llm", action="store_true", help="Write high-confidence LLM fixes to disk (they are still tested)")
    p.add_argument("--dry-run", action="store_true", help="Show what would change without touching files")
    p.add_argument("--report", type=Path, default=Path("patchpilot-report.md"), help="Markdown report path")
    p.add_argument("--json", type=Path, help="Also write a JSON report here")
    p.add_argument("--post-note", action="store_true", help="Post the report on the GitLab merge request")
    p.add_argument("--fail-on", choices=SEVERITY_ORDER + ["moderate"], help="Exit 1 if a finding at or above this severity is left unfixed")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    reports = [(name, path) for name, path in (("npm-audit", args.npm_audit), ("pip-audit", args.pip_audit), ("semgrep", args.semgrep)) if path]
    if not reports:
        print("Give at least one scanner report: --npm-audit, --pip-audit or --semgrep.", file=sys.stderr)
        return 2

    llm = None
    if args.llm:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("--llm needs ANTHROPIC_API_KEY; continuing without LLM drafts.", file=sys.stderr)
        else:
            from .llm import anthropic_completion

            llm = anthropic_completion()

    findings = load_reports(reports)
    outcome = process(findings, Options(repo=args.repo.resolve(), test_cmd=args.test_cmd, llm=llm, apply_llm=args.apply_llm, dry_run=args.dry_run))

    markdown = to_markdown(outcome)
    args.report.write_text(markdown, encoding="utf-8")
    if args.json:
        args.json.write_text(to_json(outcome), encoding="utf-8")
    print(markdown)

    if args.post_note:
        from .gitlab import GitLabConfigError, post_mr_note

        try:
            post_mr_note(markdown)
            print("Posted the report on the merge request.")
        except GitLabConfigError as exc:
            print(str(exc), file=sys.stderr)

    worst = outcome.worst_routed()
    if args.fail_on and worst and severity_rank(worst) >= severity_rank(args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
