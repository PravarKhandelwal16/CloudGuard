import os
from typing import Optional
from .rules import match_rules_in_line
from .candidate_extractor import extract_candidates_from_line, Candidate
from ..utils.masking import mask_secret

try:
    from ml.predictor import predict_candidate
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False


class FindingCandidate:
    def __init__(
        self,
        category: str,
        severity: str,
        detection_method: str,
        confidence: float,
        file_path: str,
        line_number: Optional[int],
        masked_preview: str,
        reason: str,
        recommendation: str,
        rule_id: Optional[str] = None
    ):
        self.category = category
        self.severity = severity
        self.detection_method = detection_method
        self.confidence = confidence
        self.file_path = file_path
        self.line_number = line_number
        self.masked_preview = masked_preview
        self.reason = reason
        self.recommendation = recommendation
        self.rule_id = rule_id

    def to_dict(self):
        return {
            "category": self.category,
            "severity": self.severity,
            "detection_method": self.detection_method,
            "confidence": round(self.confidence, 4),
            "file_path": self.file_path,
            "line_number": self.line_number,
            "masked_preview": self.masked_preview,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "rule_id": self.rule_id
        }


def process_line_findings(
    rel_path: str,
    line_number: int,
    line_content: str,
    ml_threshold: float = 0.50
) -> list[FindingCandidate]:
    """
    Applies rules, candidate extraction, and ML classifier to a single line.
    Combines rule and ML evidence according to the documented decision policy.
    Never stores or returns unmasked secrets.
    """
    rule_matches = match_rules_in_line(line_content)
    candidates = extract_candidates_from_line(line_content, line_number, rule_matches)

    findings: list[FindingCandidate] = []
    seen_dedup = set()

    for cand in candidates:
        masked = mask_secret(cand.value)
        dedup_key = (rel_path, line_number, masked)
        if dedup_key in seen_dedup:
            continue

        # Evaluate with ML if available
        ml_result = None
        if ML_AVAILABLE:
            try:
                ml_result = predict_candidate(
                    cand.value,
                    context=cand.context,
                    is_quoted=cand.is_quoted,
                    threshold=ml_threshold
                )
            except Exception:
                ml_result = None

        # Decision Policy:
        # 1. Known-format rule match
        if cand.rule_match:
            rm = cand.rule_match
            if ml_result and ml_result.get("is_secret"):
                detection_method = "Rule + ML"
                combined_conf = max(rm["confidence"], ml_result["confidence"])
            else:
                detection_method = "Rule"
                combined_conf = rm["confidence"]

            seen_dedup.add(dedup_key)
            findings.append(FindingCandidate(
                category=rm["category"],
                severity=rm["severity"],
                detection_method=detection_method,
                confidence=combined_conf,
                file_path=rel_path,
                line_number=line_number,
                masked_preview=masked,
                reason=rm["reason"],
                recommendation=rm["recommendation"],
                rule_id=rm.get("rule_id")
            ))

        # 2. Heuristic/ML candidate
        elif ml_result and ml_result.get("is_secret"):
            # Requires adequate contextual evidence
            prob = ml_result["probability"]
            severity = "High" if prob >= 0.85 else "Medium"
            conf_percent = int(prob * 100)

            seen_dedup.add(dedup_key)
            findings.append(FindingCandidate(
                category="Sensitive Token / Secret",
                severity=severity,
                detection_method="ML",
                confidence=prob,
                file_path=rel_path,
                line_number=line_number,
                masked_preview=masked,
                reason=f"Random Forest ML classifier flagged candidate string as likely secret (probability: {conf_percent}%)",
                recommendation="Inspect this value. If it is an active credential, rotate it immediately and store it in environment variables or a secrets manager.",
                rule_id="ml_classifier_rf"
            ))

    return findings

