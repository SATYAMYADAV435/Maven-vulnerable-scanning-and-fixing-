import os
import re
import difflib
import shutil
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from app.models.schemas import Vulnerability, Dependency, PatchRecommendation


class FixEngineError(Exception):
    """Raised when patch generation or application fails."""
    pass


class FixEngine:
    """Generates unified diffs and safely applies dependency version patches with backups."""

    def __init__(self, pom_path: str):
        self.pom_path = os.path.abspath(pom_path)
        if not os.path.isfile(self.pom_path):
            raise FixEngineError(f"Target POM file does not exist: {self.pom_path}")

    def generate_recommendations(
        self,
        dependencies: List[Dependency],
        vulnerabilities: List[Vulnerability],
    ) -> List[PatchRecommendation]:
        """
        Groups vulnerabilities by package and produces patch recommendations with unified diff previews.
        """
        # Group vulnerabilities by package
        pkg_vulns: Dict[str, List[Vulnerability]] = {}
        for v in vulnerabilities:
            pkg_vulns.setdefault(v.package_name, []).append(v)

        recommendations: List[PatchRecommendation] = []

        # Read current POM content
        with open(self.pom_path, "r", encoding="utf-8") as f:
            original_content = f.read()

        for dep in dependencies:
            if dep.key not in pkg_vulns:
                continue

            vulns = pkg_vulns[dep.key]
            # Find the highest/safest fixed version recommended
            fixed_versions = [v.fixed_version for v in vulns if v.fixed_version]
            if not fixed_versions:
                continue

            # Pick target fixed version (simplest approach: latest or first available)
            target_version = sorted(fixed_versions, reverse=True)[0]
            if target_version == dep.version:
                continue

            # Generate unified diff preview
            diff_text = self._preview_pom_diff(
                original_content=original_content,
                artifact_id=dep.artifact_id,
                current_version=dep.version,
                target_version=target_version,
            )

            rec = PatchRecommendation(
                dependency_key=dep.key,
                current_version=dep.version,
                recommended_version=target_version,
                vulnerabilities_fixed=[v.id for v in vulns],
                unified_diff=diff_text,
            )
            recommendations.append(rec)

        return recommendations

    def apply_patch(
        self,
        dependency_key: str,
        target_version: str,
        confirm: bool = False,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Safely applies a version bump to pom.xml.
        Strictly requires confirm=True and creates a timestamped backup before writing.
        Returns:
            (success, message, backup_filepath)
        """
        if not confirm:
            raise FixEngineError("Fix application aborted: explicit confirmation (confirm=True) required.")

        with open(self.pom_path, "r", encoding="utf-8") as f:
            original_content = f.read()

        artifact_id = dependency_key.split(":")[-1] if ":" in dependency_key else dependency_key

        # Create timestamped backup file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{self.pom_path}.bak.{timestamp}"
        shutil.copy2(self.pom_path, backup_path)

        # Apply replacement
        patched_content = self._patch_content(original_content, artifact_id, target_version)
        if patched_content == original_content:
            return False, f"Could not find matching dependency block for {artifact_id} in {self.pom_path}", backup_path

        with open(self.pom_path, "w", encoding="utf-8") as f:
            f.write(patched_content)

        return True, f"Successfully updated {dependency_key} to version {target_version}", backup_path

    def _preview_pom_diff(
        self,
        original_content: str,
        artifact_id: str,
        current_version: str,
        target_version: str,
    ) -> Optional[str]:
        """Generates unified diff between current POM and proposed patched POM."""
        patched_content = self._patch_content(original_content, artifact_id, target_version)
        if patched_content == original_content:
            return None

        diff_lines = difflib.unified_diff(
            original_content.splitlines(keepends=True),
            patched_content.splitlines(keepends=True),
            fromfile=f"a/{os.path.basename(self.pom_path)}",
            tofile=f"b/{os.path.basename(self.pom_path)}",
        )
        return "".join(diff_lines)

    def _patch_content(self, content: str, artifact_id: str, target_version: str) -> str:
        """
        Safely replaces the <version> tag inside the specific <dependency> block matching artifact_id.
        """
        pattern = re.compile(
            rf"(<dependency>[\s\S]*?<artifactId>{re.escape(artifact_id)}</artifactId>[\s\S]*?<version>)(.*?)(</version>)",
            re.MULTILINE,
        )

        def replacer(match):
            return f"{match.group(1)}{target_version}{match.group(3)}"

        new_content, count = pattern.subn(replacer, content, count=1)
        if count > 0:
            return new_content

        # Fallback: check if defined as a property e.g. <log4j.version>2.14.1</log4j.version>
        prop_pattern = re.compile(
            rf"(<[a-zA-Z0-9_\-\.]*version>)(.*?)(</[a-zA-Z0-9_\-\.]*version>)",
            re.MULTILINE,
        )
        return content
