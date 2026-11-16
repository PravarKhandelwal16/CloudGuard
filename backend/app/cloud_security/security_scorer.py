"""
Security Scorer for CloudGuard Cloud Security Auditor.

Calculates an infrastructure security posture score from 0 to 100 with
deductions based on severity, and handles assessment coverage and incomplete states.
"""

from typing import List, Dict, Any, Tuple, Optional
from .severity_engine import Severity, CheckStatus


class SecurityScorer:
    # Transparent score deductions
    SEVERITY_DEDUCTIONS = {
        Severity.CRITICAL: 30,
        Severity.HIGH: 15,
        Severity.MEDIUM: 7,
        Severity.LOW: 2,
        Severity.INFORMATIONAL: 0
    }

    @classmethod
    def calculate_score(
        cls,
        findings: List[Dict[str, Any]],
        total_resources_assessed: int,
        unassessed_count: int = 0,
        permission_denied_services: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Calculates cloud security score and detailed breakdown.
        
        If assessment coverage is insufficient (e.g., critical permission errors
        preventing any resource inspection), returns an incomplete status.
        """
        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFORMATIONAL: 0,
        }
        status_counts = {
            CheckStatus.FAILED: 0,
            CheckStatus.PASSED: 0,
            CheckStatus.WARNING: 0,
            CheckStatus.NOT_ASSESSED: 0,
        }

        total_deduction = 0

        for f in findings:
            status = f.get("status", CheckStatus.FAILED)
            severity = f.get("severity", Severity.LOW)

            if status in status_counts:
                status_counts[status] += 1
            else:
                status_counts[CheckStatus.FAILED] += 1

            if status in (CheckStatus.FAILED, CheckStatus.WARNING):
                if severity in counts:
                    counts[severity] += 1
                else:
                    counts[Severity.MEDIUM] += 1
                total_deduction += cls.SEVERITY_DEDUCTIONS.get(severity, 7)
            elif status == CheckStatus.NOT_ASSESSED:
                status_counts[CheckStatus.NOT_ASSESSED] += 1

        # Check coverage
        permission_denied = permission_denied_services or []
        is_complete = True
        coverage_status = "complete"
        coverage_notes = []

        if len(permission_denied) > 0:
            is_complete = False
            coverage_status = "incomplete"
            denied_list = ", ".join(permission_denied)
            coverage_notes.append(
                f"AWS IAM permissions were missing for services: {denied_list}. "
                f"Results for these services could not be assessed and are not counted as secure."
            )

        if total_resources_assessed == 0 and status_counts[CheckStatus.FAILED] == 0:
            # Nothing was assessed
            is_complete = False
            coverage_status = "incomplete"
            coverage_notes.append("No cloud resources were discovered or accessible to evaluate.")
            score = None
        else:
            score = max(0, 100 - total_deduction)

        return {
            "score": score,
            "is_complete": is_complete,
            "coverage_status": coverage_status,
            "coverage_notes": " ".join(coverage_notes) if coverage_notes else "Full assessment completed.",
            "total_resources_assessed": total_resources_assessed,
            "checks_passed": status_counts[CheckStatus.PASSED],
            "checks_failed": status_counts[CheckStatus.FAILED],
            "checks_warned": status_counts[CheckStatus.WARNING],
            "checks_not_assessed": status_counts[CheckStatus.NOT_ASSESSED] + unassessed_count,
            "critical_count": counts[Severity.CRITICAL],
            "high_count": counts[Severity.HIGH],
            "medium_count": counts[Severity.MEDIUM],
            "low_count": counts[Severity.LOW],
            "info_count": counts[Severity.INFORMATIONAL],
            "deductions_applied": total_deduction,
        }
