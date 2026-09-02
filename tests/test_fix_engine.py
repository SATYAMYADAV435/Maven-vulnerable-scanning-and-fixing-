import os
import shutil
import pytest
from app.models.schemas import Dependency, Vulnerability, SeverityLevel
from app.scanner.fix_engine import FixEngine, FixEngineError


def test_unified_diff_generation(tmp_path):
    pom_file = tmp_path / "pom.xml"
    pom_content = """<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>"""
    pom_file.write_text(pom_content, encoding="utf-8")

    fixer = FixEngine(str(pom_file))
    dep = Dependency(group_id="org.apache.logging.log4j", artifact_id="log4j-core", version="2.14.1")
    vuln = Vulnerability(
        id="CVE-2021-44228",
        severity=SeverityLevel.CRITICAL,
        package_name="org.apache.logging.log4j:log4j-core",
        current_version="2.14.1",
        fixed_version="2.17.1",
    )

    recs = fixer.generate_recommendations([dep], [vuln])
    assert len(recs) == 1
    assert recs[0].recommended_version == "2.17.1"
    assert recs[0].unified_diff is not None
    assert "-            <version>2.14.1</version>" in recs[0].unified_diff
    assert "+            <version>2.17.1</version>" in recs[0].unified_diff


def test_safe_patch_application_with_backup(tmp_path):
    pom_file = tmp_path / "pom.xml"
    pom_content = """<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
    </dependencies>
</project>"""
    pom_file.write_text(pom_content, encoding="utf-8")

    fixer = FixEngine(str(pom_file))

    # Calling without confirmation must fail
    with pytest.raises(FixEngineError):
        fixer.apply_patch("org.apache.logging.log4j:log4j-core", "2.17.1", confirm=False)

    # Calling with confirmation should succeed and create a backup file
    success, msg, backup_path = fixer.apply_patch(
        "org.apache.logging.log4j:log4j-core", "2.17.1", confirm=True
    )
    assert success is True
    assert backup_path is not None
    assert os.path.isfile(backup_path)

    # Verify original pom was updated
    new_content = pom_file.read_text(encoding="utf-8")
    assert "<version>2.17.1</version>" in new_content
    assert "<version>2.14.1</version>" not in new_content

    # Verify backup retained the original version
    with open(backup_path, "r", encoding="utf-8") as bf:
        bak_content = bf.read()
    assert "<version>2.14.1</version>" in bak_content
