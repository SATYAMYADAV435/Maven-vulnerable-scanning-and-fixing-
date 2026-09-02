from typing import List, Optional
from app.models.schemas import Vulnerability, HeuristicFinding, SeverityLevel, RiskScore


class RiskEngine:
    """Computes a transparent 0-100 security score with severity breakdown."""

    FORMULA_DESCRIPTION = (
        "Base Score = 100. Penalties: Critical (-20), High (-10), Medium (-4), Low (-1). "
        "Source Heuristics: Critical (-5), High (-3), Medium (-1). Floored at 0."
    )

    @classmethod
    def calculate_score(
        cls,
        vulnerabilities: List[Vulnerability],
        heuristic_findings: Optional[List[HeuristicFinding]] = None,
    ) -> RiskScore:
        """
        Calculates project security risk score from 0 to 100.
        """
        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0

        # Vulnerability penalties
        for v in vulnerabilities:
            if v.severity == SeverityLevel.CRITICAL:
                crit_count += 1
            elif v.severity == SeverityLevel.HIGH:
                high_count += 1
            elif v.severity == SeverityLevel.MEDIUM:
                med_count += 1
            elif v.severity == SeverityLevel.LOW:
                low_count += 1

        vuln_penalties = (crit_count * 20) + (high_count * 10) + (med_count * 4) + (low_count * 1)

        # Heuristic source penalties (weighted lower due to heuristic nature)
        source_penalties = 0
        if heuristic_findings:
            for h in heuristic_findings:
                if h.severity == SeverityLevel.CRITICAL:
                    source_penalties += 5
                elif h.severity == SeverityLevel.HIGH:
                    source_penalties += 3
                elif h.severity == SeverityLevel.MEDIUM:
                    source_penalties += 1

        raw_score = 100 - (vuln_penalties + source_penalties)
        final_score = max(0, min(100, raw_score))

        # Letter grade classification
        if final_score >= 90:
            grade = "A"
        elif final_score >= 70:
            grade = "B"
        elif final_score >= 50:
            grade = "C"
        else:
            grade = "D"

        return RiskScore(
            score=final_score,
            grade=grade,
            formula=cls.FORMULA_DESCRIPTION,
            critical_count=crit_count,
            high_count=high_count,
            medium_count=med_count,
            low_count=low_count,
            total_vulnerabilities=len(vulnerabilities),
        )
