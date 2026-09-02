import os
from typing import List, Dict, Tuple
from app.models.schemas import Dependency, ProjectInfo
from app.scanner.pom_parser import PomParser, PomParseError


class DependencyScanner:
    """Discovers and aggregates all Maven dependencies across single and multi-module projects."""

    def __init__(self, root_dir: str):
        self.root_dir = os.path.abspath(root_dir)

    def scan_project(self) -> Tuple[ProjectInfo, List[Dependency]]:
        """
        Scans root pom.xml and child modules (if multi-module), aggregating all dependencies.
        Returns (ProjectInfo, List[Dependency]).
        """
        root_pom = os.path.join(self.root_dir, "pom.xml")
        if not os.path.isfile(root_pom):
            raise PomParseError(f"No pom.xml found in project root: {self.root_dir}")

        parser = PomParser(root_pom)
        main_project, direct_deps = parser.parse()

        all_deps: Dict[str, Dependency] = {}
        for dep in direct_deps:
            all_deps[dep.key] = dep

        # If multi-module, parse each submodule POM found in subdirectories
        for module in main_project.modules:
            mod_pom = os.path.join(self.root_dir, module, "pom.xml")
            if os.path.isfile(mod_pom):
                try:
                    sub_parser = PomParser(mod_pom)
                    _, sub_deps = sub_parser.parse()
                    for s_dep in sub_deps:
                        # If not already present or needs version
                        if s_dep.key not in all_deps:
                            all_deps[s_dep.key] = s_dep
                except Exception:
                    # Non-fatal for individual submodules in best-effort mode
                    pass

        return main_project, list(all_deps.values())
