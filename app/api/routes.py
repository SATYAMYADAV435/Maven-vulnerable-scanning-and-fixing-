import os
from typing import Dict, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

from app.models.schemas import ScanResult
from app.scanner.orchestrator import ScannerOrchestrator
from app.scanner.pom_parser import PomParseError
from app.zip_handler import ZipSecurityError
from app.scanner.fix_engine import FixEngine
from app.reports.json_report import JsonReportGenerator
from app.reports.html_report import HtmlReportGenerator

router = APIRouter()

# In-memory storage for active scan results
_SCAN_RESULTS: Dict[str, ScanResult] = {}
_SCAN_TARGETS: Dict[str, str] = {}  # scan_id -> target directory or extracted path


class ScanPathRequest(BaseModel):
    path: str
    mode: Optional[str] = "online"
    source_scan: Optional[bool] = True
    fail_on: Optional[str] = "critical"


class PatchRequest(BaseModel):
    dependency_key: str
    target_version: str
    confirm: bool = False


@router.get("/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "Maven Application Security Vulnerability Scanner",
        "version": "1.0.0",
        "offline_db_available": True,
    }


@router.post("/scan")
async def scan_project(
    request: Request,
    file: Optional[UploadFile] = File(None),
    path: Optional[str] = Form(None),
    mode: Optional[str] = Form("online"),
    source_scan: Optional[bool] = Form(True),
    fail_on: Optional[str] = Form("critical"),
):
    """
    Scans a Maven project via uploaded ZIP file, multipart form, or JSON payload.
    """
    orchestrator = ScannerOrchestrator()

    # Support JSON body if form fields are empty
    if file is None and not path:
        try:
            body = await request.json()
            if isinstance(body, dict):
                path = body.get("path")
                mode = body.get("mode", mode or "online")
                source_scan = body.get("source_scan", source_scan if source_scan is not None else True)
                fail_on = body.get("fail_on", fail_on or "critical")
        except Exception:
            pass

    if file is not None:
        content = await file.read()
        target_source = content
    elif path is not None and path.strip():
        target_source = path.strip()
    else:
        raise HTTPException(status_code=400, detail="Must provide either a ZIP file upload or a directory path.")

    try:
        scan_result, temp_dir = orchestrator.run_scan(
            target_path_or_zip=target_source,
            mode=mode,
            source_scan_enabled=source_scan,
            fail_on=fail_on,
        )
    except (PomParseError, ZipSecurityError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan execution error: {str(e)}")

    # Store scan result
    _SCAN_RESULTS[scan_result.scan_id] = scan_result
    _SCAN_TARGETS[scan_result.scan_id] = temp_dir or (path if path else "")

    return {
        "scan_id": scan_result.scan_id,
        "status": "COMPLETED",
        "project": scan_result.project.model_dump(),
        "security_score": scan_result.risk_score.score,
        "grade": scan_result.risk_score.grade,
        "vulnerabilities_count": len(scan_result.vulnerabilities),
        "heuristic_findings_count": len(scan_result.heuristic_findings),
        "patches_count": len(scan_result.patches),
    }


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    """Retrieves full scan details by ID."""
    if scan_id not in _SCAN_RESULTS:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found.")
    return _SCAN_RESULTS[scan_id]


@router.get("/report/{scan_id}")
def get_report(scan_id: str, format: str = Query("json", pattern="^(html|json)$")):
    """
    Generates and returns the full 10-section report in HTML or JSON format.
    """
    if scan_id not in _SCAN_RESULTS:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found.")

    scan_result = _SCAN_RESULTS[scan_id]

    if format == "html":
        html_str = HtmlReportGenerator().generate(scan_result)
        return HTMLResponse(content=html_str)
    else:
        json_str = JsonReportGenerator.generate(scan_result)
        return Response(content=json_str, media_type="application/json")


@router.post("/patch/{scan_id}")
def apply_patch(scan_id: str, req: PatchRequest):
    """
    Safely applies a recommended version patch to pom.xml.
    Requires confirm=True and creates a timestamped backup before modifying.
    """
    if scan_id not in _SCAN_RESULTS:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found.")

    if not req.confirm:
        raise HTTPException(
            status_code=400,
            detail="Confirmation required. Set 'confirm': true to apply the patch.",
        )

    target_dir = _SCAN_TARGETS.get(scan_id)
    if not target_dir or not os.path.isdir(target_dir):
        raise HTTPException(
            status_code=400,
            detail="Cannot apply patch: original project directory not accessible or was a temporary upload.",
        )

    pom_path = os.path.join(target_dir, "pom.xml")
    if not os.path.isfile(pom_path):
        raise HTTPException(status_code=404, detail="pom.xml not found in project directory.")

    fixer = FixEngine(pom_path)
    success, message, backup_file = fixer.apply_patch(
        dependency_key=req.dependency_key,
        target_version=req.target_version,
        confirm=True,
    )

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {
        "status": "SUCCESS",
        "message": message,
        "backup_file": backup_file,
    }
