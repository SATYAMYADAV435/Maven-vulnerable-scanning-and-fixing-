import sys
import os
import argparse
from typing import List
from app.config import load_config, redact_secrets
from app.models.schemas import SeverityLevel
from app.scanner.orchestrator import ScannerOrchestrator
from app.scanner.pom_parser import PomParseError
from app.zip_handler import ZipSecurityError, SafeZipExtractor
from app.scanner.fix_engine import FixEngine


def parse_args(args: List[str] = None):
    parser = argparse.ArgumentParser(
        description="Maven Application Security Vulnerability Scanner (SIH J-001)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit Codes:
  0 : Scan completed successfully; no threshold violation.
  1 : Security threshold exceeded (e.g., Critical/High vulnerability detected).
  2 : Operational or configuration error (invalid path, malformed POM, bad ZIP).

Examples:
  python -m app.cli ./my-maven-project
  python scanner.py project.zip --mode offline --fail-on high
  python -m app.cli . --format html,json --output ./scan-reports
        """,
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to Maven project directory or ZIP archive (default: current directory).",
    )
    parser.add_argument(
        "--config",
        "-c",
        default="scanner.yml",
        help="Path to configuration file (default: scanner.yml).",
    )
    parser.add_argument(
        "--mode",
        "-m",
        choices=["online", "offline"],
        help="Scanning mode: 'online' (OSV.dev live) or 'offline' (cache & labeled demo DB).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Severity threshold that triggers an exit code 1 failure.",
    )
    parser.add_argument(
        "--format",
        "-f",
        default="html,json",
        help="Comma-separated report formats to generate (default: 'html,json').",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="./reports",
        help="Directory where generated reports will be stored (default: ./reports).",
    )
    parser.add_argument(
        "--no-source",
        action="store_true",
        help="Disable heuristic static analysis on Java source files.",
    )
    parser.add_argument(
        "--apply-fixes",
        action="store_true",
        help="Interactively apply available dependency version fixes with automatic backup.",
    )

    return parser.parse_args(args)


def main(argv: List[str] = None) -> int:
    args = parse_args(argv)

    # 1. Load config
    try:
        config = load_config(args.config)
    except Exception as e:
        print(redact_secrets(f"[ERROR] Failed to load configuration '{args.config}': {e}"), file=sys.stderr)
        return 2

    # 2. Run Scanner Orchestrator
    orchestrator = ScannerOrchestrator(config)
    temp_dir = None
    try:
        scan_result, temp_dir = orchestrator.run_scan(
            target_path_or_zip=args.target,
            mode=args.mode,
            source_scan_enabled=not args.no_source,
            fail_on=args.fail_on,
        )
    except (PomParseError, ZipSecurityError, FileNotFoundError) as e:
        print(redact_secrets(f"[ERROR] Scan rejected / failed: {e}"), file=sys.stderr)
        return 2
    except Exception as e:
        print(redact_secrets(f"[FATAL] Scanner operational failure: {e}"), file=sys.stderr)
        return 2
    finally:
        # Note: We keep temp_dir until reports and optional fixes are processed if needed
        pass

    # 3. Print CLI Summary
    r = scan_result
    print("\n" + "=" * 65)
    print("      MAVEN SECURITY VULNERABILITY SCANNER — REPORT SUMMARY")
    print("=" * 65)
    print(f"Project:      {r.project.group_id}:{r.project.artifact_id}:{r.project.version}")
    print(f"Scan Mode:    {r.database_info.mode.upper()} ({r.database_info.source_name})")
    if r.database_info.is_demo_data:
        print(f"WARNING:      {r.database_info.warning_label}")
    print(f"Duration:     {r.duration_seconds:.2f} seconds")
    print(f"Dependencies: {len(r.dependencies)} analyzed")
    print("-" * 65)
    print(f"SECURITY SCORE: {r.risk_score.score} / 100   [ Grade {r.risk_score.grade} ]")
    print(f"Formula:        {r.risk_score.formula}")
    print("-" * 65)
    print("Vulnerability Breakdown:")
    print(f"  • CRITICAL: {r.risk_score.critical_count}")
    print(f"  • HIGH:     {r.risk_score.high_count}")
    print(f"  • MEDIUM:   {r.risk_score.medium_count}")
    print(f"  • LOW:      {r.risk_score.low_count}")
    print(f"  • TOTAL:    {r.risk_score.total_vulnerabilities}")

    if r.heuristic_findings:
        print(f"\nSource Heuristics: {len(r.heuristic_findings)} potential anti-patterns detected")
        print("  (Flagged as heuristic/static — not proven exploitable)")

    # 4. Generate Reports
    formats = [fmt.strip().lower() for fmt in args.format.split(",") if fmt.strip()]
    saved_reports = orchestrator.save_reports(
        scan_result=scan_result,
        output_dir=args.output,
        formats=formats,
    )
    if saved_reports:
        print("-" * 65)
        print("Generated Reports:")
        for rep in saved_reports:
            print(f"  • {rep}")

    # 5. Optional Apply-Fixes Flow
    if args.apply_fixes and r.patches:
        target_pom = os.path.join(args.target, "pom.xml")
        if os.path.isfile(target_pom):
            print("\nAvailable Dependency Fixes:")
            fixer = FixEngine(target_pom)
            for p in r.patches:
                print(f"\n- Dependency: {p.dependency_key}")
                print(f"  Current: {p.current_version} -> Recommended: {p.recommended_version}")
                if p.unified_diff:
                    print(p.unified_diff)

                choice = input(f"Apply fix for {p.dependency_key} to {p.recommended_version}? [y/N]: ").strip().lower()
                if choice in ("y", "yes"):
                    ok, msg, bak = fixer.apply_patch(p.dependency_key, p.recommended_version, confirm=True)
                    print(f"  {msg}")
                    if bak:
                        print(f"  (Backup created at: {bak})")

    # Cleanup temp extraction if ZIP was uploaded
    if temp_dir:
        SafeZipExtractor.cleanup(temp_dir)

    # 6. Evaluate exit threshold
    fail_on = (args.fail_on or config.security.fail_on).lower()
    score_threshold = config.security.min_score

    threshold_exceeded = False
    if fail_on == "critical" and r.risk_score.critical_count > 0:
        threshold_exceeded = True
    elif fail_on == "high" and (r.risk_score.critical_count > 0 or r.risk_score.high_count > 0):
        threshold_exceeded = True
    elif fail_on == "medium" and (r.risk_score.critical_count > 0 or r.risk_score.high_count > 0 or r.risk_score.medium_count > 0):
        threshold_exceeded = True
    elif fail_on == "low" and r.risk_score.total_vulnerabilities > 0:
        threshold_exceeded = True

    if r.risk_score.score < score_threshold:
        threshold_exceeded = True

    print("=" * 65)
    if threshold_exceeded:
        print(f"RESULT: FAILED — Security threshold '{fail_on}' or min score {score_threshold} breached!")
        return 1
    else:
        print("RESULT: PASSED — All security checks within configured tolerances.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
