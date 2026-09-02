import os
import re
from typing import List, Dict, Optional, Tuple
import defusedxml.ElementTree as ET
from app.models.schemas import Dependency, ProjectInfo


class PomParseError(Exception):
    """Raised when pom.xml is missing, invalid XML, or cannot be parsed."""
    pass


class PomParser:
    """Parses Maven pom.xml safely, resolving properties, parents, and dependency management."""

    def __init__(self, pom_path: str):
        self.pom_path = os.path.abspath(pom_path)
        if not os.path.isfile(self.pom_path):
            raise PomParseError(f"POM file not found: {self.pom_path}")
        self.base_dir = os.path.dirname(self.pom_path)
        self.properties: Dict[str, str] = {}
        self.dep_management: Dict[str, str] = {}  # "groupId:artifactId" -> version

    def parse(self) -> Tuple[ProjectInfo, List[Dependency]]:
        """
        Parses the POM and returns (ProjectInfo, List[Dependency]).
        """
        try:
            tree = ET.parse(self.pom_path)
            root = tree.getroot()
        except ET.ParseError as e:
            raise PomParseError(f"Malformed XML in {self.pom_path}: {e}")
        except Exception as e:
            raise PomParseError(f"Could not read POM {self.pom_path}: {e}")

        # Extract namespace if present
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        def find(elem, tag: str):
            return elem.find(f"{ns}{tag}")

        def findall(elem, tag: str):
            return elem.findall(f"{ns}{tag}")

        def text_of(elem, tag: str, default: str = "") -> str:
            child = find(elem, tag)
            if child is not None and child.text:
                return child.text.strip()
            return default

        # 1. Parent Coordinates
        parent_elem = find(root, "parent")
        parent_group = ""
        parent_version = ""
        if parent_elem is not None:
            parent_group = text_of(parent_elem, "groupId")
            parent_version = text_of(parent_elem, "version")

        # 2. Project Coordinates
        group_id = text_of(root, "groupId", default=parent_group)
        artifact_id = text_of(root, "artifactId", default="unknown")
        version = text_of(root, "version", default=parent_version or "1.0.0")
        packaging = text_of(root, "packaging", default="jar")

        # 3. Built-in properties
        self.properties["project.groupId"] = group_id
        self.properties["pom.groupId"] = group_id
        self.properties["project.artifactId"] = artifact_id
        self.properties["pom.artifactId"] = artifact_id
        self.properties["project.version"] = version
        self.properties["pom.version"] = version

        # 4. Extract <properties>
        props_elem = find(root, "properties")
        if props_elem is not None:
            for prop in props_elem:
                tag_name = prop.tag.split("}")[-1]
                if prop.text:
                    self.properties[tag_name] = prop.text.strip()

        # 5. Extract <modules>
        modules: List[str] = []
        modules_elem = find(root, "modules")
        if modules_elem is not None:
            for mod_elem in findall(modules_elem, "module"):
                if mod_elem.text:
                    modules.append(mod_elem.text.strip())

        # 6. Extract <dependencyManagement>
        dep_mgmt_elem = find(root, "dependencyManagement")
        if dep_mgmt_elem is not None:
            deps_container = find(dep_mgmt_elem, "dependencies")
            if deps_container is not None:
                for dep_elem in findall(deps_container, "dependency"):
                    d_group = self._resolve_str(text_of(dep_elem, "groupId"))
                    d_art = self._resolve_str(text_of(dep_elem, "artifactId"))
                    d_ver = self._resolve_str(text_of(dep_elem, "version"))
                    if d_group and d_art and d_ver:
                        self.dep_management[f"{d_group}:{d_art}"] = d_ver

        # 7. Extract direct <dependencies>
        dependencies: List[Dependency] = []
        deps_elem = find(root, "dependencies")
        if deps_elem is not None:
            for dep_elem in findall(deps_elem, "dependency"):
                d_group = self._resolve_str(text_of(dep_elem, "groupId"))
                d_art = self._resolve_str(text_of(dep_elem, "artifactId"))
                d_ver = self._resolve_str(text_of(dep_elem, "version"))
                scope = self._resolve_str(text_of(dep_elem, "scope", default="compile"))

                # Resolve version from dependencyManagement if missing in direct dep
                resolved = True
                if not d_ver:
                    d_ver = self.dep_management.get(f"{d_group}:{d_art}", "")
                    if not d_ver:
                        d_ver = "unspecified"
                        resolved = False

                if d_group and d_art:
                    dependencies.append(
                        Dependency(
                            group_id=d_group,
                            artifact_id=d_art,
                            version=d_ver,
                            scope=scope,
                            is_transitive=False,
                            resolved=resolved,
                        )
                    )

        project_info = ProjectInfo(
            group_id=self._resolve_str(group_id),
            artifact_id=self._resolve_str(artifact_id),
            version=self._resolve_str(version),
            packaging=packaging,
            modules=modules,
        )

        return project_info, dependencies

    def _resolve_str(self, val: str) -> str:
        """Substitute ${property.name} occurrences iteratively."""
        if not val:
            return ""

        pattern = re.compile(r"\$\{([^}]+)\}")
        iterations = 0
        while "${" in val and iterations < 5:
            iterations += 1
            matches = pattern.findall(val)
            if not matches:
                break
            for match in matches:
                if match in self.properties:
                    val = val.replace(f"${{{match}}}", self.properties[match])
        return val
