from patchpilot.findings import load_reports, parse_npm_audit, version_key


def test_npm_audit_parsing(demo):
    findings = load_reports([("npm-audit", demo / "reports" / "npm-audit.json")])
    by_pkg = {f.package: f for f in findings}
    assert set(by_pkg) == {"jsonwebtoken", "lodash", "minimist"}
    assert by_pkg["lodash"].fixed_in == "4.17.21" and not by_pkg["lodash"].major_bump
    assert by_pkg["jsonwebtoken"].major_bump
    assert by_pkg["lodash"].id == "GHSA-35jh-r3h4-6jhm"
    # Worst first
    assert findings[0].severity == "critical"


def test_npm_fix_only_in_lockfile_has_no_target_version():
    data = {"vulnerabilities": {"qs": {"severity": "high", "isDirect": False, "via": ["express"], "range": "<6.10.3", "fixAvailable": True}}}
    (finding,) = parse_npm_audit(data)
    assert finding.fixed_in is None and finding.direct is False


def test_pip_audit_parsing(demo):
    findings = load_reports([("pip-audit", demo / "reports" / "pip-audit.json")])
    assert {f.package: f.fixed_in for f in findings} == {"pyyaml": "5.4", "requests": "2.31.0"}


def test_semgrep_parsing(demo):
    findings = load_reports([("semgrep", demo / "reports" / "semgrep.json")])
    yaml_finding = next(f for f in findings if "pyyaml" in f.rule)
    assert yaml_finding.autofix == "yaml.safe_load(raw)"
    assert yaml_finding.severity == "high"
    sql = next(f for f in findings if "sql" in f.rule)
    assert sql.autofix is None and sql.start_line == 13


def test_version_key_ordering():
    assert version_key("4.17.21") > version_key("4.17.3")
    assert version_key("^1.2.6") == (1, 2, 6)
    assert version_key("2.0.0-beta.1") == (2, 0, 0)
