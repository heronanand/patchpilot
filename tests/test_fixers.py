import json

from patchpilot.findings import Finding, load_reports
from patchpilot.fixers import apply_semgrep_autofix, fix_npm_dependency, fix_pip_dependency, rollback


def _npm(demo, package):
    return next(f for f in load_reports([("npm-audit", demo / "reports" / "npm-audit.json")]) if f.package == package)


def test_npm_bump_keeps_range_prefix(demo):
    result = fix_npm_dependency(_npm(demo, "lodash"), demo)
    assert result.applied
    assert json.loads((demo / "package.json").read_text())["dependencies"]["lodash"] == "^4.17.21"


def test_npm_bump_in_dev_dependencies(demo):
    result = fix_npm_dependency(_npm(demo, "minimist"), demo)
    assert result.applied
    assert json.loads((demo / "package.json").read_text())["devDependencies"]["minimist"] == "~1.2.6"


def test_npm_major_upgrade_is_routed(demo):
    result = fix_npm_dependency(_npm(demo, "jsonwebtoken"), demo)
    assert not result.applied and "major" in result.summary
    assert json.loads((demo / "package.json").read_text())["dependencies"]["jsonwebtoken"] == "^8.5.1"


def test_pip_pin_preserves_comment(demo):
    finding = next(f for f in load_reports([("pip-audit", demo / "reports" / "pip-audit.json")]) if f.package == "requests")
    result = fix_pip_dependency(finding, demo)
    assert result.applied
    assert "requests==2.31.0  # HTTP client" in (demo / "requirements.txt").read_text()


def test_pip_name_matching_is_case_insensitive(demo):
    finding = next(f for f in load_reports([("pip-audit", demo / "reports" / "pip-audit.json")]) if f.package == "pyyaml")
    assert fix_pip_dependency(finding, demo).applied
    assert (demo / "requirements.txt").read_text().startswith("PyYAML==5.4")


def test_semgrep_autofix_replaces_exact_span_and_rolls_back(demo):
    finding = next(f for f in load_reports([("semgrep", demo / "reports" / "semgrep.json")]) if f.autofix)
    before = (demo / "app.py").read_text()
    result = apply_semgrep_autofix(finding, demo)
    after = (demo / "app.py").read_text()
    assert result.applied
    assert "return yaml.safe_load(raw)" in after and "yaml.load(" not in after
    rollback(result)
    assert (demo / "app.py").read_text() == before


def test_missing_manifest_is_routed(tmp_path):
    finding = Finding(id="x", source="npm-audit", kind="dependency", severity="high", title="t", package="lodash", fixed_in="4.17.21")
    result = fix_npm_dependency(finding, tmp_path)
    assert not result.applied and "package.json" in result.summary
