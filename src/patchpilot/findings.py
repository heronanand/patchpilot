"""Normalise security-scanner output into one Finding shape.

Supported inputs:
  * npm audit --json (report version 2)
  * pip-audit -f json
  * semgrep --json
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_ALIASES = {"moderate": "medium", "warning": "medium", "error": "high"}
_SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


@dataclass
class Finding:
    """One problem reported by a scanner, in a scanner-independent shape."""

    id: str
    source: str  # "npm-audit" | "pip-audit" | "semgrep"
    kind: str  # "dependency" | "code"
    severity: str
    title: str
    # Dependency findings
    package: str | None = None
    installed: str | None = None
    fixed_in: str | None = None
    major_bump: bool = False
    direct: bool = True
    # Code findings
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    start_offset: int | None = None
    end_offset: int | None = None
    autofix: str | None = None
    rule: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def location(self) -> str:
        if self.kind == "dependency":
            return f"{self.package} {self.installed or ''}".strip()
        if self.start_line and self.end_line and self.end_line != self.start_line:
            return f"{self.path}:{self.start_line}-{self.end_line}"
        return f"{self.path}:{self.start_line}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def severity_rank(severity: str) -> int:
    sev = (severity or "").lower()
    sev = SEVERITY_ALIASES.get(sev, sev)
    # Unknown severities rank as "high" so they are never silently ignored.
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else SEVERITY_ORDER.index("high")


def version_key(version: str) -> tuple[int, ...]:
    """Sort key for dotted versions; pre-release suffixes are ignored."""
    parts = []
    for piece in re.split(r"[.\-+]", version.strip().lstrip("vV=<>~^ ")):
        match = re.match(r"\d+", piece)
        if not match:
            break
        parts.append(int(match.group()))
    return tuple(parts) or (0,)


def parse_npm_audit(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for name, vuln in sorted((data.get("vulnerabilities") or {}).items()):
        advisories = [v for v in vuln.get("via", []) if isinstance(v, dict)]
        title = advisories[0].get("title") if advisories else f"Vulnerable dependency via {', '.join(map(str, vuln.get('via', [])))}"
        advisory_id = advisories[0].get("url", "").rsplit("/", 1)[-1] if advisories else name
        fix = vuln.get("fixAvailable")
        fixed_in, major = None, False
        if isinstance(fix, dict) and fix.get("name") == name:
            fixed_in, major = fix.get("version"), bool(fix.get("isSemVerMajor"))
        findings.append(
            Finding(
                id=advisory_id or name,
                source="npm-audit",
                kind="dependency",
                severity=vuln.get("severity", "unknown"),
                title=title,
                package=name,
                installed=vuln.get("range"),
                fixed_in=fixed_in,
                major_bump=major,
                direct=bool(vuln.get("isDirect", False)),
                extra={"fix_available": fix if not isinstance(fix, dict) else True},
            )
        )
    return findings


def parse_pip_audit(data: dict[str, Any] | list[Any]) -> list[Finding]:
    deps = data.get("dependencies", []) if isinstance(data, dict) else data
    findings: list[Finding] = []
    for dep in deps:
        for vuln in dep.get("vulns", []):
            fixes = sorted(vuln.get("fix_versions") or [], key=version_key)
            desc = (vuln.get("description") or "").strip().split("\n")[0]
            findings.append(
                Finding(
                    id=vuln.get("id", "unknown"),
                    source="pip-audit",
                    kind="dependency",
                    # pip-audit does not report severity; treat as high until triaged.
                    severity=vuln.get("severity", "high"),
                    title=desc[:140] or vuln.get("id", "Vulnerable dependency"),
                    package=dep.get("name"),
                    installed=dep.get("version"),
                    fixed_in=fixes[0] if fixes else None,
                    major_bump=bool(fixes and version_key(fixes[0])[:1] != version_key(dep.get("version", "0"))[:1]),
                    direct=True,
                    extra={"aliases": vuln.get("aliases", [])},
                )
            )
    return findings


def parse_semgrep(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        start, end = result.get("start", {}), result.get("end", {})
        rule = result.get("check_id", "semgrep-rule")
        findings.append(
            Finding(
                id=f"{rule.rsplit('.', 1)[-1]}@{result.get('path')}:{start.get('line')}",
                source="semgrep",
                kind="code",
                severity=_SEMGREP_SEVERITY.get(extra.get("severity", "WARNING"), "medium"),
                title=extra.get("message", rule).strip().split("\n")[0][:160],
                path=result.get("path"),
                start_line=start.get("line"),
                end_line=end.get("line"),
                start_offset=start.get("offset"),
                end_offset=end.get("offset"),
                autofix=extra.get("fix"),
                rule=rule,
            )
        )
    return findings


PARSERS = {"npm-audit": parse_npm_audit, "pip-audit": parse_pip_audit, "semgrep": parse_semgrep}


def load_reports(reports: Iterable[tuple[str, Path]]) -> list[Finding]:
    """Load (scanner, path) pairs and return every finding, worst first."""
    findings: list[Finding] = []
    for scanner, path in reports:
        if scanner not in PARSERS:
            raise ValueError(f"Unknown scanner '{scanner}'. Use one of: {', '.join(PARSERS)}")
        with open(path, encoding="utf-8") as fh:
            findings.extend(PARSERS[scanner](json.load(fh)))
    return sorted(findings, key=lambda f: -severity_rank(f.severity))
