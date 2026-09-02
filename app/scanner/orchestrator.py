import os
import time
import uuid
from datetime import datetime
from typing import Optional, List, Tuple
from app.models.schemas import (
    ScanResult,
    ScanConfig,
    ProjectInfo,
    SeverityLevel,
)
from app.config import AppConfig, load_config
from app.zip_handler import SafeZipExtractor, ZipSecurityError
from app.scanner.pom_parser import PomParseError
from app.scanner.dependency_scanner import DependencyScanner
from app.scanner.vulnerability_engine import VulnerabilityEngine
from app.scanner.source_scanner import SourceScanner
from app.scanner.risk_engine import RiskEngine
from app.scanner.fix_engine import FixEngine
from app.reports.json_report import JsonReportGenerator
from app.reports.html_report import HtmlReportGenerator


class ScannerOrchestrator:
    """Orchestrates the entire Maven Security Scan pipeline."""

    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or load_config()

    def run_scan(
        self,
        target_path_or_zip: str | bytes,
        mode: Optional[str] = None,
        source_scan_enabled: Optional[bool] = None,
        fail_on: Optional[str] = None,
    ) -> Tuple[ScanResult, Optional[str]]:
        """
        Executes the end-to-end scan pipeline:
        ZIP safety -> POM parsing -> Vulnerability engine -> Source scan -> Risk engine -> Fix engine.
        Returns:
            (ScanResult, temp_dir_to_cleanup)
        """
        start_time = time.time()
        scan_id = str(uuid.uuid4())[:8]

        eff_mode = (mode or self.config.database.mode).lower()
        eff_source_scan = (
            source_scan_enabled
            if source_scan_enabled is not None
            else self.config.scan.source_analysis
        )
        eff_fail_on = (fail_on or self.config.security.fail_on).lower()

        temp_dir: Optional[str] = None
        target_dir: str = ""

        # Step 1: Input handling (safe ZIP extraction vs local directory)
        if isinstance(target_path_or_zip, bytes) or (
            isinstance(target_path_or_zip, str)
            and (target_path_or_zip.endswith(".zip") or os.path.isfile(target_path_or_zip))
        ):
            extractor = SafeZipExtractor(
                max_uncompressed_bytes=self.config.scan.max_uncompressed_size_mb * 1024 * 1024,
                max_file_count=self.config.scan.max_files,
                allowed_extensions=self.config.scan.allowed_extensions,
            )
            temp_dir, _ = extractor.extract_to_temp(target_path_or_zip)
            target_dir = temp_dir
        else:
            target_dir = os.path.abspath(target_path_or_zip)
            if not os.path.isdir(target_dir):
                raise PomParseError(f"Target path does not exist or is not a directory: {target_dir}")

        # Step 2: Ingest POM and dependencies
        dep_scanner = DependencyScanner(target_dir)
        project_info, dependencies = dep_scanner.scan_project()

        # Step 3: Vulnerability Engine
        vuln_engine = VulnerabilityEngine(
            mode=eff_mode,
            api_url=self.config.database.osv_api_url,
            db_path=self.config.database.sqlite_path,
            cache_ttl_hours=self.config.database.cache_ttl_hours,
        )
        vulnerabilities, db_info = vuln_engine.scan_dependencies(dependencies)

        # Step 4: Source analysis (heuristic)
        heuristic_findings = []
        if eff_source_scan:
            source_scanner = SourceScanner(target_dir)
            heuristic_findings = source_scanner.scan()

        # Step 5: Risk Scoring
        risk_score = RiskEngine.calculate_score(vulnerabilities, heuristic_findings)

        # Step 6: Fix Recommendations & diff generation
        root_pom = os.path.join(target_dir, "pom.xml")
        patches = []
        if os.path.isfile(root_pom):
            fix_engine = FixEngine(root_pom)
            patches = fix_engine.generate_recommendations(dependencies, vulnerabilities)

        duration = time.time() - start_time

        scan_config = ScanConfig(
            target_path=target_path_or_zip if isinstance(target_path_or_zip, str) else "uploaded_archive.zip",
            mode=eff_mode,
            source_scan_enabled=eff_source_scan,
            fail_on=eff_fail_on,
            db_source=db_info.source_name,
        )

        scan_result = ScanResult(
            scan_id=scan_id,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            duration_seconds=round(duration, 3),
            project=project_info,
            config=scan_config,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities,
            heuristic_findings=heuristic_findings,
            risk_score=risk_score,
            patches=patches,
            database_info=db_info,
        )

        return scan_result, temp_dir

    def save_reports(
        self,
        scan_result: ScanResult,
        output_dir: str = "./reports",
        formats: Optional[List[str]] = None,
    ) -> List[str]:
        """Saves reports to output directory in requested formats (html, json)."""
        formats = formats or self.config.report.formats
        os.makedirs(output_dir, exist_ok=True)
        saved_files: List[str] = []

        prefix = f"scan_{scan_result.project.artifact_id}_{scan_result.scan_id}"

        if "json" in formats:
            json_content = JsonReportGenerator.generate(scan_result)
            json_path = os.path.join(output_dir, f"{prefix}.json")
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(json_content)
            saved_files.append(os.path.abspath(json_path))

        if "html" in formats:
            html_content = HtmlReportGenerator().generate(scan_result)
            html_path = os.path.join(output_dir, f"{prefix}.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            saved_files.append(os.path.abspath(html_path))

        return saved_files
