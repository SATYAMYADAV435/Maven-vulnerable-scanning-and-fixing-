from app.models.schemas import Vulnerability, HeuristicFinding, SeverityLevel
from app.scanner.risk_engine import RiskEngine


def make_vuln(severity: SeverityLevel) -> Vulnerability:
    return Vulnerability(
        id="CVE-TEST",
        severity=severity,
        package_name="test:pkg",
        current_version="1.0.0",
    )


def test_clean_project_score():
    score_res = RiskEngine.calculate_score([])
    assert score_res.score == 100
    assert score_res.grade == "A"
    assert score_res.total_vulnerabilities == 0


def test_score_penalties_formula():
    vulns = [
        make_vuln(SeverityLevel.CRITICAL),  # -20
        make_vuln(SeverityLevel.HIGH),      # -10
        make_vuln(SeverityLevel.MEDIUM),    # -4
        make_vuln(SeverityLevel.LOW),       # -1
    ]
    # 100 - (20 + 10 + 4 + 1) = 65
    score_res = RiskEngine.calculate_score(vulns)
    assert score_res.score == 65
    assert score_res.grade == "C"
    assert score_res.critical_count == 1
    assert score_res.high_count == 1
    assert score_res.medium_count == 1
    assert score_res.low_count == 1


def test_score_floor_at_zero():
    # 6 Criticals = -120 -> should floor at 0
    vulns = [make_vuln(SeverityLevel.CRITICAL) for _ in range(6)]
    score_res = RiskEngine.calculate_score(vulns)
    assert score_res.score == 0
    assert score_res.grade == "D"


def test_heuristic_source_findings_penalty():
    findings = [
        HeuristicFinding(
            file_path="App.java",
            line_number=10,
            category="Hardcoded Secret",
            severity=SeverityLevel.HIGH,  # -3
            snippet="String s = 'xyz'",
            explanation="test",
        )
    ]
    score_res = RiskEngine.calculate_score([], findings)
    # 100 - 3 = 97
    assert score_res.score == 97
    assert score_res.grade == "A"
