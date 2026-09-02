import os
import sys
import pytest

# Ensure repository root is on sys.path for test imports
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def sample_pom_path():
    return os.path.join(FIXTURES_DIR, "sample_pom.xml")


@pytest.fixture
def multi_module_pom_path():
    return os.path.join(FIXTURES_DIR, "multi_module_pom.xml")


@pytest.fixture
def malformed_pom_path():
    return os.path.join(FIXTURES_DIR, "malformed_pom.xml")


@pytest.fixture
def sample_project_dir():
    return os.path.join(FIXTURES_DIR, "sample_project")
