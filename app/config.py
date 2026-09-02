import os
import re
import yaml
from typing import List, Dict, Any
from pydantic import BaseModel, Field


class ScanConfigModel(BaseModel):
    source_analysis: bool = True
    max_uncompressed_size_mb: int = 50
    max_files: int = 1000
    allowed_extensions: List[str] = Field(
        default_factory=lambda: [
            ".xml", ".java", ".properties", ".yaml", ".yml", ".json", ".md", ".txt"
        ]
    )


class SecurityConfigModel(BaseModel):
    fail_on: str = "critical"
    min_score: int = 70


class DatabaseConfigModel(BaseModel):
    mode: str = "online"
    sqlite_path: str = "vulnerabilities.db"
    osv_api_url: str = "https://api.osv.dev/v1/querybatch"
    cache_ttl_hours: int = 24


class ReportConfigModel(BaseModel):
    formats: List[str] = Field(default_factory=lambda: ["html", "json"])
    output_dir: str = "./reports"


class LoggingConfigModel(BaseModel):
    redact_secrets: bool = True


class AppConfig(BaseModel):
    scan: ScanConfigModel = Field(default_factory=ScanConfigModel)
    security: SecurityConfigModel = Field(default_factory=SecurityConfigModel)
    database: DatabaseConfigModel = Field(default_factory=DatabaseConfigModel)
    report: ReportConfigModel = Field(default_factory=ReportConfigModel)
    logging: LoggingConfigModel = Field(default_factory=LoggingConfigModel)


_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token|auth|bearer)\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?"),
    re.compile(r"(?i)(ghp_[A-Za-z0-9_]{36}|AKIA[0-9A-Z]{16})"),
]


def redact_secrets(text: str) -> str:
    """Redact passwords, API tokens, and secrets from logs."""
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(r"\1: [REDACTED]", redacted)
    return redacted


def load_config(config_path: str = "scanner.yml") -> AppConfig:
    """Load configuration from YAML file or return defaults."""
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return AppConfig(**data)
        except Exception:
            return AppConfig()
    return AppConfig()
