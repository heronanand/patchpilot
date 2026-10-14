"""Deterministic fixers for routine findings.

Each fixer returns a FixResult. A fixer never guesses: if a finding needs a
judgement call (a major version jump, no published fix, a code change with no
known-safe rewrite) it declines with a reason, and the pipeline routes the
finding to an engineer.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding, version_key


@dataclass
class FixResult:
    finding: Finding
    applied: bool
    summary: str
    files: dict[str, str] = field(default_factory=dict)  # path -> original content (for rollback)
    suggestion: str | None = None
    fixer: str = ""


def _decline(finding: Finding, reason: str, fixer: str) -> FixResult:
    return FixResult(finding=finding, applied=False, summary=reason, fixer=fixer)


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def fix_npm_dependency(finding: Finding, repo: Path) -> FixResult:
    name = "npm-bump"
    if not finding.direct:
        return _decline(finding, "Transitive dependency: needs a lockfile update or an override, review by hand.", name)
    if not finding.fixed_in:
        return _decline(finding, "No fixed version published for this package.", name)
    if finding.major_bump:
        return _decline(finding, f"Fix needs a major upgrade to {finding.fixed_in}; check for breaking changes.", name)

    manifest = repo / "package.json"
    if not manifest.exists():
        return _decline(finding, "package.json not found.", name)
    original = manifest.read_text(encoding="utf-8")
    pkg = json.loads(original)
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        spec = (pkg.get(section) or {}).get(finding.package)
        if spec is None:
            continue
        prefix = re.match(r"^[\^~]?", spec).group()
        current = re.sub(r"^[\^~>=<\s]*", "", spec)
        if version_key(current) >= version_key(finding.fixed_in):
            return _decline(finding, f"package.json already allows {spec}; refresh the lockfile.", name)
        pkg[section][finding.package] = f"{prefix}{finding.fixed_in}"
        manifest.write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
        return FixResult(
            finding=finding,
            applied=True,
            summary=f"Bumped {finding.package} from {spec} to {prefix}{finding.fixed_in} in {section}.",
            files={str(manifest): original},
            fixer=name,
        )
    return _decline(finding, f"{finding.package} is not declared in package.json.", name)


_REQ_LINE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?\s*(?P<op>==|>=|~=)?\s*(?P<ver>[^\s;#]+)?(?P<rest>.*)$")


def fix_pip_dependency(finding: Finding, repo: Path) -> FixResult:
    name = "pip-bump"
    if not finding.fixed_in:
        return _decline(finding, "No fixed version published for this package.", name)
    if finding.major_bump:
        return _decline(finding, f"Fix needs a major upgrade to {finding.fixed_in}; check for breaking changes.", name)

    req = repo / "requirements.txt"
    if not req.exists():
        return _decline(finding, "requirements.txt not found.", name)
    original = req.read_text(encoding="utf-8")
    lines = original.splitlines(keepends=True)
    for i, line in enumerate(lines):
        match = _REQ_LINE.match(line.strip())
        if not match or _normalise(match.group("name")) != _normalise(finding.package or ""):
            continue
        op = match.group("op") or "=="
        extras = match.group("extras") or ""
        rest = match.group("rest") or ""
        newline = "\n" if line.endswith("\n") else ""
        lines[i] = f"{match.group('name')}{extras}{op}{finding.fixed_in}{rest}{newline}"
        req.write_text("".join(lines), encoding="utf-8")
        return FixResult(
            finding=finding,
            applied=True,
            summary=f"Pinned {finding.package} to {op}{finding.fixed_in} in requirements.txt (was {match.group('ver') or 'unpinned'}).",
            files={str(req): original},
            fixer=name,
        )
    return _decline(finding, f"{finding.package} is not listed in requirements.txt.", name)


def apply_semgrep_autofix(finding: Finding, repo: Path) -> FixResult:
    name = "semgrep-autofix"
    if finding.autofix is None:
        return _decline(finding, "Rule has no published autofix.", name)
    if finding.start_offset is None or finding.end_offset is None:
        return _decline(finding, "Scanner did not report byte offsets for the match.", name)
    target = repo / (finding.path or "")
    if not target.exists():
        return _decline(finding, f"{finding.path} not found.", name)
    original = target.read_text(encoding="utf-8")
    raw = original.encode("utf-8")
    patched = raw[: finding.start_offset] + finding.autofix.encode("utf-8") + raw[finding.end_offset :]
    target.write_text(patched.decode("utf-8"), encoding="utf-8")
    return FixResult(
        finding=finding,
        applied=True,
        summary=f"Applied the rule's autofix at {finding.location()}.",
        files={str(target): original},
        fixer=name,
    )


def routine_fix(finding: Finding, repo: Path) -> FixResult:
    """Pick the deterministic fixer for a finding, if any."""
    if finding.source == "npm-audit":
        return fix_npm_dependency(finding, repo)
    if finding.source == "pip-audit":
        return fix_pip_dependency(finding, repo)
    if finding.source == "semgrep":
        return apply_semgrep_autofix(finding, repo)
    return _decline(finding, f"No fixer for source {finding.source}.", "none")


def rollback(result: FixResult) -> None:
    for path, content in result.files.items():
        Path(path).write_text(content, encoding="utf-8")
