from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Dependency(BaseModel):
    group_id: str
    artifact_id: str
    version: str
    scope: str = "compile"
    is_transitive: bool = False
    parent_dependency: Optional[str] = None
    resolved: bool = True

    @property
    def key(self) -> str:
        return f"{self.group_id}:{self.artifact_id}"


class Vulnerability(BaseModel):
    id: str = Field(..., description="CVE or GHSA identifier")
    title: str = ""
    description: str = ""
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_ranges: List[str] = Field(default_factory=list)
    fixed_version: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    source: str = Field(default="osv", description="'osv' or 'offline_demo'")
    is_demo_data: bool = False
    package_name: str
    current_version: str


class HeuristicFinding(BaseModel):
    file_path: str
    line_number: int
    category: str
    severity: SeverityLevel
    snippet: str
    explanation: str
    confidence: str = "heuristic/static — not proven exploitable"


class PatchRecommendation(BaseModel):
    dependency_key: str
    current_version: str
    recommended_version: str
    vulnerabilities_fixed: List[str] = Field(default_factory=list)
    unified_diff: Optional[str] = None


class RiskScore(BaseModel):
    score: int = Field(..., ge=0, le=100)
    grade: str = Field(..., description="'A', 'B', 'C', or 'D'")
    formula: str
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_vulnerabilities: int = 0


class ProjectInfo(BaseModel):
    group_id: str = "unknown"
    artifact_id: str = "unknown"
    version: str = "unknown"
    packaging: str = "jar"
    modules: List[str] = Field(default_factory=list)


class ScanConfig(BaseModel):
    target_path: str
    mode: str = "online"  # 'online' or 'offline'
    source_scan_enabled: bool = True
    fail_on: str = "critical"  # 'critical', 'high', 'medium', 'low'
    db_source: str = "OSV.dev / Local SQLite Cache"


class DatabaseInfo(BaseModel):
    mode: str
    source_name: str
    is_demo_data: bool
    version_or_date: str
    warning_label: Optional[str] = None


class ScanResult(BaseModel):
    scan_id: str
    timestamp: str
    duration_seconds: float
    project: ProjectInfo
    config: ScanConfig
    dependencies: List[Dependency] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    heuristic_findings: List[HeuristicFinding] = Field(default_factory=list)
    risk_score: RiskScore
    patches: List[PatchRecommendation] = Field(default_factory=list)
    database_info: DatabaseInfo
