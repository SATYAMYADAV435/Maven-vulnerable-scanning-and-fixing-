import os
import re
from typing import List
from app.models.schemas import HeuristicFinding, SeverityLevel


class SourceScanner:
    """Performs lightweight regex/heuristic static security checks across Java source files."""

    RULES = [
        {
            "category": "Hardcoded Secret / API Key",
            "severity": SeverityLevel.HIGH,
            "pattern": re.compile(r"""(?i)(?:password|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*=\s*["']([A-Za-z0-9_\-\.\/+=]{8,})["']"""),
            "explanation": "Potential hardcoded credential or API secret found in source code. Use environment variables or a secrets manager.",
        },
        {
            "category": "Hardcoded AWS Access Key",
            "severity": SeverityLevel.CRITICAL,
            "pattern": re.compile(r"""(AKIA[0-9A-Z]{16})"""),
            "explanation": "Detected hardcoded AWS Access Key ID. Hardcoded cloud keys present an immediate exfiltration risk.",
        },
        {
            "category": "Command Injection Risk",
            "severity": SeverityLevel.HIGH,
            "pattern": re.compile(r"""(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\([^)]*\+[^)]*\)"""),
            "explanation": "Process or command execution built using dynamic string concatenation can allow arbitrary command injection.",
        },
        {
            "category": "SQL Injection Risk",
            "severity": SeverityLevel.HIGH,
            "pattern": re.compile(r"""(?:executeQuery|executeUpdate|execute)\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE).*\+"""),
            "explanation": "Constructing SQL statements via dynamic string concatenation is susceptible to SQL injection. Use PreparedStatement.",
        },
        {
            "category": "Weak Cryptography (MD5 / SHA-1)",
            "severity": SeverityLevel.MEDIUM,
            "pattern": re.compile(r"""MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']\s*\)"""),
            "explanation": "MD5 and SHA-1 have known collision vulnerabilities. Use SHA-256, SHA-384, or SHA-512 instead.",
        },
        {
            "category": "Weak Encryption (DES / ECB Mode)",
            "severity": SeverityLevel.MEDIUM,
            "pattern": re.compile(r"""Cipher\.getInstance\s*\(\s*["'](?:DES|AES/ECB|DESede)"""),
            "explanation": "DES is cryptographically broken, and ECB mode does not provide serious ciphertext confidentiality. Use AES/GCM.",
        },
        {
            "category": "Insecure Deserialization Risk",
            "severity": SeverityLevel.HIGH,
            "pattern": re.compile(r"""(?:new\s+ObjectInputStream\([^)]*\)\.readObject|ois\.readObject\(\))"""),
            "explanation": "Deserializing untrusted data with ObjectInputStream can lead to remote code execution (e.g. gadget chains).",
        },
        {
            "category": "Potential Path Traversal",
            "severity": SeverityLevel.LOW,
            "pattern": re.compile(r"""new\s+File\s*\([^,\)]+,\s*[A-Za-z0-9_]+\)"""),
            "explanation": "Constructing File paths directly from variable input without path normalization may allow directory traversal (zip-slip or path-slip).",
        },
    ]

    def __init__(self, root_dir: str, max_file_bytes: int = 2 * 1024 * 1024):
        self.root_dir = os.path.abspath(root_dir)
        self.max_file_bytes = max_file_bytes

    def scan(self) -> List[HeuristicFinding]:
        """Scans all .java files under root_dir and returns detected heuristic findings."""
        findings: List[HeuristicFinding] = []

        for dirpath, _, filenames in os.walk(self.root_dir):
            for fname in filenames:
                if not fname.endswith(".java"):
                    continue

                full_path = os.path.join(dirpath, fname)
                try:
                    if os.path.getsize(full_path) > self.max_file_bytes:
                        continue  # Skip unusually large files

                    rel_path = os.path.relpath(full_path, self.root_dir)
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()

                    for idx, line in enumerate(lines, start=1):
                        clean_line = line.strip()
                        if not clean_line or clean_line.startswith("//") or clean_line.startswith("/*"):
                            continue

                        for rule in self.RULES:
                            if rule["pattern"].search(clean_line):
                                findings.append(
                                    HeuristicFinding(
                                        file_path=rel_path,
                                        line_number=idx,
                                        category=rule["category"],
                                        severity=rule["severity"],
                                        snippet=clean_line[:120],
                                        explanation=rule["explanation"],
                                        confidence="heuristic/static — not proven exploitable",
                                    )
                                )
                except Exception:
                    # Gracefully continue on unreadable individual files
                    continue

        return findings
