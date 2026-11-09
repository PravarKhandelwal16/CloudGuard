import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class RuleDefinition:
    rule_id: str
    name: str
    category: str
    severity: str  # Critical, High, Medium, Low
    confidence: float
    regex: re.Pattern
    extract_group: int  # Group to extract as candidate, 0 for full match
    reason: str
    recommendation: str


RULES: list[RuleDefinition] = [
    RuleDefinition(
        rule_id="private_key",
        name="Private Key Block",
        category="Private Key",
        severity="Critical",
        confidence=0.98,
        regex=re.compile(r"-----BEGIN (?:[A-Z0-9_\-]+ )*(?:PRIVATE KEY|PRIVATE KEY BLOCK)-----"),
        extract_group=0,
        reason="Detected cryptographic private key block header",
        recommendation="Revoke this private key immediately, generate a fresh key pair, and store private keys in a secure key store or vault."
    ),
    RuleDefinition(
        rule_id="aws_secret_key",
        name="AWS Secret Access Key",
        category="AWS Secret Key",
        severity="Critical",
        confidence=0.92,
        regex=re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        extract_group=1,
        reason="Matched AWS secret access key contextual assignment pattern",
        recommendation="Revoke the secret access key in AWS IAM immediately. Use EC2 IAM roles or AWS Secrets Manager instead of static credentials."
    ),
    RuleDefinition(
        rule_id="aws_access_key_id",
        name="AWS Access Key ID",
        category="AWS Access Key ID",
        severity="High",
        confidence=0.90,
        regex=re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"),
        extract_group=1,
        reason="Matched standard AWS Access Key ID format (AKIA/ASIA/...)",
        recommendation="Remove the AWS access key ID from source code. Rotate the corresponding key pair in AWS IAM."
    ),
    RuleDefinition(
        rule_id="github_token",
        name="GitHub Access Token",
        category="GitHub Token",
        severity="Critical",
        confidence=0.95,
        regex=re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{80,255})\b"),
        extract_group=1,
        reason="Matched GitHub Personal Access Token prefix and structure",
        recommendation="Revoke the token in GitHub Settings > Developer settings > Personal access tokens. Configure tokens via GitHub Actions secrets."
    ),
    RuleDefinition(
        rule_id="db_connection_uri",
        name="Database Connection URI with Password",
        category="Database Credential",
        severity="Critical",
        confidence=0.90,
        regex=re.compile(
            r"(?:postgres|postgresql|mysql|mongodb|redis|mssql|oracle):\/\/[a-zA-Z0-9_\-\.%]+:(.+?)@(?=[a-zA-Z0-9_\-\.]+(?::[0-9]+|\/|\s|$|['\"]))"
        ),
        extract_group=1,
        reason="Detected database connection URI containing an embedded plaintext password",
        recommendation="Remove credentials from database URIs. Inject database connection parameters via environment variables or a managed secrets store."
    ),
    RuleDefinition(
        rule_id="generic_api_key",
        name="Generic API Key / Secret Token",
        category="API Token",
        severity="High",
        confidence=0.85,
        regex=re.compile(
            r"(?i)(?:api[_-]?key|api[_-]?secret|app[_-]?secret|access[_-]?token|client[_-]?secret|secret[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,128})['\"]"
        ),
        extract_group=1,
        reason="Matched API token or client secret assignment pattern",
        recommendation="Remove the API key from source code, rotate it with the service provider, and load it via environment variables."
    ),
    RuleDefinition(
        rule_id="generic_password",
        name="Generic Password Assignment",
        category="Password",
        severity="High",
        confidence=0.80,
        regex=re.compile(
            r"(?i)(?:password|passwd|db_password|db_pass|user_password|secret_key)\s*[:=]\s*['\"]([^'\"\s]{6,128})['\"]"
        ),
        extract_group=1,
        reason="Detected hardcoded password or credential assignment",
        recommendation="Remove hardcoded password. Rotate passwords across all environments and inject values through environment variables."
    ),
    RuleDefinition(
        rule_id="jwt_token",
        name="JSON Web Token (JWT)",
        category="JWT Token",
        severity="Medium",
        confidence=0.75,
        regex=re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        extract_group=1,
        reason="Detected JSON Web Token (JWT) structure",
        recommendation="Ensure static JWTs are not committed to source control. Issue tokens dynamically and store signing keys in secure configuration."
    ),
]


def match_rules_in_line(line: str) -> list[dict]:
    """Matches all rules against a single line of text."""
    matches = []
    for rule in RULES:
        for match in rule.regex.finditer(line):
            candidate = match.group(rule.extract_group) if rule.extract_group <= len(match.groups()) else match.group(0)
            matches.append({
                "rule_id": rule.rule_id,
                "name": rule.name,
                "category": rule.category,
                "severity": rule.severity,
                "confidence": rule.confidence,
                "candidate": candidate,
                "reason": rule.reason,
                "recommendation": rule.recommendation,
                "start": match.start(),
                "end": match.end(),
            })
    return matches
