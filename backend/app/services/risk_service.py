from collections import Counter

SEVERITY_DEDUCTIONS = {
    "Critical": 30,
    "High": 15,
    "Medium": 7,
    "Low": 2
}


def calculate_security_score(findings: list) -> tuple[int, dict[str, int]]:
    """
    Calculates the CloudGuard security score and severity counts.
    Score formula: max(0, 100 - sum(severity * weight))
    Returns:
        (score, counts_dict)
    """
    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Total": len(findings)
    }

    total_deduction = 0
    for f in findings:
        severity = getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else "Medium")
        # Normalize casing
        sev_title = severity.capitalize() if severity else "Medium"
        if sev_title in SEVERITY_DEDUCTIONS:
            counts[sev_title] += 1
            total_deduction += SEVERITY_DEDUCTIONS[sev_title]
        else:
            counts["Medium"] += 1
            total_deduction += SEVERITY_DEDUCTIONS["Medium"]

    score = max(0, 100 - total_deduction)
    return score, counts

