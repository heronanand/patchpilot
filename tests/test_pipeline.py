import json
import sys

from patchpilot.cli import main
from patchpilot.findings import load_reports, severity_rank
from patchpilot.pipeline import Options, process
from patchpilot.report import to_markdown

ALL = ("npm-audit", "pip-audit", "semgrep")


def _all_findings(demo):
    return load_reports([(name, demo / "reports" / f"{name}.json") for name in ALL])


def test_routine_fixes_applied_rest_routed(demo):
    outcome = process(_all_findings(demo), Options(repo=demo))
    fixed = {r.finding.package or r.finding.rule for r in outcome.fixed}
    routed = {r.finding.package or r.finding.rule for r in outcome.routed}
    assert {"lodash", "minimist", "pyyaml", "requests"} <= fixed
    assert "jsonwebtoken" in routed
    assert any("formatted-sql-query" in r for r in routed)
    assert severity_rank(outcome.worst_routed()) == severity_rank("medium")


def test_failing_tests_roll_back_every_change(demo):
    before = {p: (demo / p).read_text() for p in ("package.json", "requirements.txt", "app.py")}
    fail = f'{sys.executable} -c "raise SystemExit(1)"'
    outcome = process(_all_findings(demo), Options(repo=demo, test_cmd=fail))
    assert not outcome.fixed
    assert all("Reverted" in r.summary or not r.files for r in outcome.routed)
    assert {p: (demo / p).read_text() for p in before} == before


def test_dry_run_changes_nothing(demo):
    before = (demo / "package.json").read_text()
    outcome = process(_all_findings(demo), Options(repo=demo, dry_run=True))
    assert (demo / "package.json").read_text() == before
    assert all(r.summary.startswith("[dry run]") for r in outcome.fixed)


def test_llm_draft_is_attached_not_applied_by_default(demo):
    def fake_llm(system, prompt):
        assert "formatted SQL" in prompt and "13 |" in prompt
        return json.dumps({
            "replacement": '    cursor.execute("SELECT id, name FROM users WHERE name = ?", (name,))',
            "explanation": "Use a parameterised query so the name is never parsed as SQL.",
            "confidence": "high",
        })

    findings = [f for f in _all_findings(demo) if f.rule and "sql" in f.rule]
    outcome = process(findings, Options(repo=demo, llm=fake_llm))
    (routed,) = outcome.routed
    assert "LLM draft attached" in routed.summary and "WHERE name = ?" in routed.suggestion
    assert "'%s'" in (demo / "app.py").read_text()


def test_llm_fix_applied_when_allowed_and_high_confidence(demo):
    def fake_llm(system, prompt):
        return '```json\n{"replacement": "    cursor.execute(\\"SELECT id, name FROM users WHERE name = ?\\", (name,))", "explanation": "Parameterise.", "confidence": "high"}\n```'

    findings = [f for f in _all_findings(demo) if f.rule and "sql" in f.rule]
    outcome = process(findings, Options(repo=demo, llm=fake_llm, apply_llm=True, test_cmd=f'{sys.executable} -c "import ast,sys; ast.parse(open(\'app.py\').read())"'))
    assert outcome.fixed and outcome.fixed[0].fixer == "llm"
    assert 'WHERE name = ?", (name,))' in (demo / "app.py").read_text()


def test_llm_failure_never_crashes(demo):
    def broken(system, prompt):
        raise TimeoutError("API timed out")

    findings = [f for f in _all_findings(demo) if f.rule and "sql" in f.rule]
    outcome = process(findings, Options(repo=demo, llm=broken))
    assert "LLM draft failed" in outcome.routed[0].summary


def test_report_lists_both_sections(demo):
    md = to_markdown(process(_all_findings(demo), Options(repo=demo)))
    assert "#### Fixed" in md and "#### Needs an engineer" in md and "jsonwebtoken" in md


def test_cli_end_to_end(demo, tmp_path, capsys):
    report, js = tmp_path / "report.md", tmp_path / "report.json"
    args = ["--repo", str(demo), "--report", str(report), "--json", str(js), "--fail-on", "moderate"]
    for name in ALL:
        args += [f"--{name}", str(demo / "reports" / f"{name}.json")]
    assert main(args) == 1  # a moderate finding (major upgrade) is left for an engineer
    data = json.loads(js.read_text())
    assert len(data["fixed"]) == 5 and len(data["routed"]) == 2
    assert "PatchPilot security report" in report.read_text()


def test_cli_requires_a_report(capsys):
    assert main([]) == 2
