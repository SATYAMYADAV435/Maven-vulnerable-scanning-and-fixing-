import pytest
from app.scanner.pom_parser import PomParser, PomParseError


def test_parse_sample_pom(sample_pom_path):
    parser = PomParser(sample_pom_path)
    project, deps = parser.parse()

    assert project.group_id == "com.example.security"
    assert project.artifact_id == "sample-vulnerable-app"
    assert project.version == "1.0.0"

    # Verify dependency extraction and property substitution (${log4j.version} -> 2.14.1)
    dep_map = {d.key: d for d in deps}
    assert "org.apache.logging.log4j:log4j-core" in dep_map
    assert dep_map["org.apache.logging.log4j:log4j-core"].version == "2.14.1"

    assert "org.springframework:spring-core" in dep_map
    assert dep_map["org.springframework:spring-core"].version == "5.3.17"

    assert "com.fasterxml.jackson.core:jackson-databind" in dep_map
    assert dep_map["com.fasterxml.jackson.core:jackson-databind"].version == "2.13.2"


def test_parse_multi_module_pom(multi_module_pom_path):
    parser = PomParser(multi_module_pom_path)
    project, deps = parser.parse()

    assert project.group_id == "com.example.parent"
    assert "submodule-a" in project.modules

    # Verify dependencyManagement resolution
    dep_map = {d.key: d for d in deps}
    assert "org.junit.jupiter:junit-jupiter" in dep_map
    assert dep_map["org.junit.jupiter:junit-jupiter"].version == "5.9.1"


def test_parse_malformed_pom_raises_graceful_error(malformed_pom_path):
    parser = PomParser(malformed_pom_path)
    with pytest.raises(PomParseError) as exc_info:
        parser.parse()
    assert "Malformed XML" in str(exc_info.value)


def test_parse_nonexistent_file():
    with pytest.raises(PomParseError) as exc_info:
        PomParser("non_existent_pom.xml")
    assert "not found" in str(exc_info.value).lower()
