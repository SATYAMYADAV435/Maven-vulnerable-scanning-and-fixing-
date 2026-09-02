import json
from app.models.schemas import (
    ScanResult,
    ProjectInfo,
    ScanConfig,
    RiskScore,
    DatabaseInfo,
    Dependency,
    Vulnerability,
    SeverityLevel,
)
from app.reports.json_report import JsonReportGenerator
from app.reports.html_report import HtmlReportGenerator


def make_dummy_scan_result():
    return ScanResult(
        scan_id="test1234",
        timestamp="2026-09-03 12:00:00",
        duration_seconds=1.23,
        project=ProjectInfo(group_id="com.test", artifact_id="test-app", version="1.0.0"),
        config=ScanConfig(target_path=".", mode="offline"),
        dependencies=[
            Dependency(group_id="org.apache.logging.log4j", artifact_id="log4j-core", version="2.14.1")
        ],
        vulnerabilities=[
            Vulnerability(
                id="CVE-2021-44228",
                title="Log4Shell",
                severity=SeverityLevel.CRITICAL,
                package_name="org.apache.logging.log4j:log4j-core",
                current_version="2.14.1",
                fixed_version="2.17.1",
                source="offline_demo",
                is_demo_data=True,
            )
        ],
        heuristic_findings=[],
        risk_score=RiskScore(
            score=80,
            grade="B",
            formula="Base 100",
            critical_count=1,
            total_vulnerabilities=1,
        ),
        patches=[],
        database_info=DatabaseInfo(
            mode="offline",
            source_name="Offline Demo DB",
            is_demo_data=True,
            version_or_date="2026-09-01",
            warning_label="DEMO DATA",
        ),
    )


def test_reports_contain_all_10_sections():
    scan_res = make_dummy_scan_result()

    # Test JSON report
    json_str = JsonReportGenerator.generate(scan_res)
    json_dict = json.loads(json_str)

    expected_sections = [
        "section_1_executive_summary",
        "section_2_project_information",
        "section_3_security_score",
        "section_4_vulnerability_summary",
        "section_5_detailed_vulnerabilities",
        "section_6_recommended_fixes",
        "section_7_dependency_analysis",
        "section_8_scan_configuration",
        "section_9_scan_metadata",
        "section_10_database_info",
    ]

    for section in expected_sections:
        assert section in json_dict, f"Missing section: {section}"

    assert json_dict["section_1_executive_summary"]["security_score"] == 80
    assert json_dict["section_2_project_information"]["artifact_id"] == "test-app"
    assert json_dict["section_10_database_info"]["is_demo_data"] is True

    # Test HTML report
    html_str = HtmlReportGenerator().generate(scan_res)
    assert "1. Executive Summary" in html_str
    assert "2. Project Information" in html_str
    assert "3. Security Score" in html_str
    assert "4. Vulnerability Summary" in html_str
    assert "5. Detailed Vulnerabilities" in html_str
    assert "6. Recommended Fixes" in html_str
    assert "7. Dependency Analysis" in html_str
    assert "8. Scan Configuration" in html_str
    assert "9. Scan Timestamp & Duration" in html_str
    assert "10. Offline / Online Database Information" in html_str
    assert "DEMO DATA" in html_str
    assert "CVE-2021-44228" in html_str
