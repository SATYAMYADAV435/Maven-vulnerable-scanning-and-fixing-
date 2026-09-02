import os
from app.cli import main


def test_cli_exit_code_1_on_vulnerability_threshold(sample_project_dir, tmp_path):
    report_dir = str(tmp_path / "cli_reports")
    exit_code = main([
        sample_project_dir,
        "--mode", "offline",
        "--fail-on", "critical",
        "--output", report_dir,
    ])
    # sample_project has log4j-core 2.14.1 which triggers Log4Shell (CRITICAL), so exit code must be 1
    assert exit_code == 1

    # Verify report files were generated
    report_files = os.listdir(report_dir)
    assert any(f.endswith(".json") for f in report_files)
    assert any(f.endswith(".html") for f in report_files)


def test_cli_exit_code_2_on_invalid_target(tmp_path):
    invalid_path = str(tmp_path / "non_existent_folder")
    exit_code = main([invalid_path])
    assert exit_code == 2


def test_cli_exit_code_0_on_clean_pom(tmp_path):
    clean_dir = tmp_path / "clean_project"
    clean_dir.mkdir()
    clean_pom = clean_dir / "pom.xml"
    clean_pom.write_text("""<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.clean</groupId>
    <artifactId>clean-project</artifactId>
    <version>1.0.0</version>
    <dependencies></dependencies>
</project>""", encoding="utf-8")

    report_dir = str(tmp_path / "clean_reports")
    exit_code = main([
        str(clean_dir),
        "--mode", "offline",
        "--fail-on", "critical",
        "--output", report_dir,
    ])
    assert exit_code == 0
