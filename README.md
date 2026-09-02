# Maven Application Security Vulnerability Scanner (SIH J-001)

A production-quality, open-source-grade security tool tailored for Maven-based Java applications. It parses `pom.xml`, inspects direct and module dependencies, detects known CVEs via OSV.dev (with an offline labeled demo database), performs heuristic static security checks on Java source code, scores overall project risk, generates safe unified diff patches with timestamped backups, and produces comprehensive 10-section reports in HTML and JSON.

---

## Architecture & Core Pipeline

```
Maven Project → Read pom.xml → Detect Dependencies → Scan for Vulnerabilities
→ Classify Risk → Recommend Fix → Generate Report
```

```
├── app/
│   ├── main.py                     # FastAPI application factory
│   ├── cli.py                      # CLI entrypoint (python -m app.cli)
│   ├── config.py                   # Loads scanner.yml with secret redaction
│   ├── zip_handler.py              # Safe ZIP extraction (zip-slip / bomb defense)
│   ├── models/schemas.py           # Pydantic schemas (Dependency, Vulnerability, etc.)
│   ├── scanner/
│   │   ├── pom_parser.py           # XML entity defense (defusedxml) + property resolution
│   │   ├── dependency_scanner.py   # Single & multi-module dependency aggregator
│   │   ├── vulnerability_engine.py # OSV.dev API client + SQLite cache + offline fallback
│   │   ├── source_scanner.py       # Heuristic static analysis for Java sources
│   │   ├── risk_engine.py          # 0-100 score calculator & severity breakdown
│   │   ├── fix_engine.py           # Unified diff patch generation & safe backup application
│   │   └── orchestrator.py         # End-to-end scanner pipeline runner
│   ├── database/
│   │   ├── vulnerability_db.py     # SQLite cache manager & offline seed loader
│   │   └── seed_offline_db.json    # Labeled OFFLINE DEMO DB records
│   ├── reports/
│   │   ├── json_report.py          # 10-section structured JSON report generator
│   │   ├── html_report.py          # 10-section self-contained HTML report generator
│   │   └── templates/report.html   # Jinja2 template with responsive DevSecOps UI
│   └── api/routes.py               # REST endpoints (/scan, /scans/{id}, /report/{id}, /health)
├── scanner.py                      # Root executable CLI shim
├── scanner.yml                     # Default configuration
├── requirements.txt                # Python dependencies
├── Dockerfile                      # Production container image
└── .github/workflows/              # CI/CD automated security scan workflow
```

---

## Key Security Features & Guarantees

1. **No Untrusted Execution**: Never executes `mvn`, `java`, or `eval` against scanned source code. All inspection is done via safe parsing (`defusedxml` mitigating XML entity attacks and XXE, regex parsing for Java).
2. **ZIP Safety Guards**:
   - Rejects directory traversal entries containing `..` or absolute paths (zip-slip protection).
   - Enforces max uncompressed size (default: 50MB) and max file count (default: 1,000) against zip bombs.
   - Enforces an allowlist of project file extensions.
3. **Data Authenticity & Offline Labeling**:
   - Online mode queries the free OSV.dev API (`https://api.osv.dev/v1/query`) and caches results in SQLite.
   - Offline mode reads from SQLite cache or falls back to bundled demo data. All offline records are strictly marked with `"source": "offline_demo"`, `"is_demo_data": true`, and a warning banner.
4. **Safe Remediation & Backups**:
   - Patch generation outputs a unified diff preview first.
   - Applying a fix requires explicit confirmation (`confirm=True`) and creates a timestamped backup (`pom.xml.bak.YYYYMMDD_HHMMSS`) before modifying user files.
5. **No Secrets in Logs**: Credentials, tokens, and passwords matching sensitive regexes are redacted prior to stdout/logging.
6. **Heuristic Static Analysis**: All findings from source analysis (hardcoded keys, SQL concatenation, weak crypto, command execution) are clearly flagged as *"heuristic/static — not proven exploitable"*.

---

## Installation

### Prerequisites
- Python 3.11+
- Git

### Setup Virtual Environment
```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## CLI Usage

Run the scanner using `python scanner.py` or `python -m app.cli`:

```bash
# Scan current directory in online mode
python scanner.py .

# Scan an uploaded ZIP archive or folder in offline mode
python scanner.py project.zip --mode offline --fail-on critical

# Generate both HTML and JSON reports in a custom output directory
python scanner.py ./my-maven-app --format html,json --output ./scan-reports

# Interactively apply available dependency version fixes with backups
python scanner.py ./my-maven-app --apply-fixes
```

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `target` | Path to Maven project directory or ZIP archive | `.` |
| `--config`, `-c` | Path to YAML configuration file | `scanner.yml` |
| `--mode`, `-m` | `online` (OSV.dev live) or `offline` (cache & labeled demo DB) | `online` |
| `--fail-on` | Severity threshold triggering failure exit code (`critical`, `high`, `medium`, `low`) | `critical` |
| `--format`, `-f` | Comma-separated output formats (`html`, `json`) | `html,json` |
| `--output`, `-o` | Directory where reports are saved | `./reports` |
| `--no-source` | Disable heuristic static analysis on Java source files | `False` |
| `--apply-fixes` | Review diffs and apply fixes to `pom.xml` with backup | `False` |

### CLI Exit Codes

- `0`: Scan passed. Security score evaluated and no vulnerabilities exceed `--fail-on`.
- `1`: Security threshold exceeded (e.g. Critical vulnerability detected when `--fail-on critical`).
- `2`: Scanner or configuration error (invalid path, malformed XML, security exception).

---

## 10-Section Report Structure

Both JSON (`--format json`) and HTML (`--format html`) reports contain the required 10 sections:

1. **Executive Summary**: Pass/Fail status, letter grade, total vulnerabilities, critical counts.
2. **Project Information**: `groupId`, `artifactId`, `version`, packaging, submodules.
3. **Security Score**: 0–100 score, letter grade (A/B/C/D), and exact penalty formula:
   $$\text{Score} = \max(0, 100 - (20 \times N_{\text{crit}} + 10 \times N_{\text{high}} + 4 \times N_{\text{med}} + 1 \times N_{\text{low}}))$$
4. **Vulnerability Summary**: Counts categorized by severity.
5. **Detailed Vulnerabilities**: Tabular breakdown with CVE/GHSA ID, package, version, CVSS, fixed version, and data source.
6. **Recommended Fixes**: Available target versions and unified diff previews for `pom.xml`.
7. **Dependency Analysis**: Direct vs transitive counts and resolution status.
8. **Scan Configuration**: Operating mode, flags, source scan toggle.
9. **Scan Timestamp & Duration**: Execution timing and runtime metadata.
10. **Database Information**: Live API vs SQLite Cache vs Offline Demo DB status and demo warnings.

---

## FastAPI REST API

Start the backend server:
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Interactive OpenAPI Swagger docs are available at `http://localhost:8000/docs`.

### Key Endpoints

- `POST /api/scan`: Accepts ZIP file upload (multipart) or JSON `path` parameter. Returns `scan_id` and summary.
- `GET /api/scans/{id}`: Retrieves complete scan results.
- `GET /api/report/{id}?format=html|json`: Downloads or displays rendered report.
- `POST /api/patch/{id}`: Safely applies patch to `pom.xml` with backup. Requires `{"confirm": true}`.
- `GET /api/health`: Health status and database information.

---

## CI/CD Pipeline Integration

### 1. GitHub Actions (`.github/workflows/security-scan.yml`)
```yaml
name: Maven Security Scan

on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: python scanner.py . --mode online --fail-on critical --format html,json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: ./reports/
```

### 2. GitLab CI (`.gitlab-ci.yml`)
```yaml
security_scan:
  image: python:3.11
  stage: test
  script:
    - pip install -r requirements.txt
    - python scanner.py . --mode online --fail-on critical --format html,json --output ./reports
  artifacts:
    when: always
    paths:
      - reports/
```

### 3. Jenkins Pipeline (`Jenkinsfile`)
```groovy
pipeline {
    agent { docker { image 'python:3.11' } }
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install -r requirements.txt'
                sh 'python scanner.py . --mode online --fail-on critical --format html,json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: false
                }
            }
        }
    }
}
```

---

## Running Tests

Execute the complete test suite (23 tests, zero live network dependencies during tests):
```bash
pytest tests/ -v
```

---

## Docker Deployment

Build and run the container:
```bash
# Build Docker image
docker build -t maven-security-scanner .

# Run FastAPI API server
docker run -p 8000:8000 maven-security-scanner

# Run CLI scanner inside Docker on a local project
docker run -v $(pwd):/workspace maven-security-scanner python scanner.py /workspace --mode offline
```
