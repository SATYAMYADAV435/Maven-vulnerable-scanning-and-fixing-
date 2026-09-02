from app.scanner.source_scanner import SourceScanner


def test_source_scanner_detections(sample_project_dir):
    scanner = SourceScanner(sample_project_dir)
    findings = scanner.scan()

    assert len(findings) >= 3

    categories = [f.category for f in findings]
    assert any("AWS Access Key" in c for c in categories)
    assert any("Secret" in c for c in categories)
    assert any("Weak Cryptography" in c for c in categories)
    assert any("SQL Injection" in c for c in categories)

    # Verify non-negotiable constraint: Heuristic label must be present on every finding
    for f in findings:
        assert "heuristic" in f.confidence.lower()
