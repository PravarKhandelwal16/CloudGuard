import re
from typing import NamedTuple
from .entropy import calculate_entropy


class Candidate(NamedTuple):
    value: str
    context: str
    is_quoted: bool
    line_number: int
    rule_match: dict | None = None


# Suspicious variable keywords that strongly hint at secret context
SUSPICIOUS_KEYWORD_REGEX = re.compile(
    r"(?i)\b(secret|token|password|passwd|api[_-]?key|access[_-]?key|auth|bearer|private[_-]?key|client[_-]?secret|credentials|connection_string|database_url)\b"
)

# Common quoted or unquoted string extraction pattern (assignment or key-value)
ASSIGNMENT_REGEX = re.compile(
    r"""(?xi)
    (?P<key>[a-zA-Z0-9_\-\.]{2,50})       # variable or key name
    \s*[:=]\s*                            # separator
    (?P<quote>["']?)                      # optional quote
    (?P<val>[A-Za-z0-9_\-\.\/\+=@:]{8,128}) # candidate value
    (?P=quote)                            # matching quote
    """
)

# High entropy standalone token pattern (alphanumeric/special, length 16 to 128)
STANDALONE_TOKEN_REGEX = re.compile(
    r"""(?x)
    ["']?([A-Za-z0-9_\-\/\+=]{16,128})["']?
    """
)

BENIGN_IGNORE_STRINGS = {
    "true", "false", "null", "undefined", "none", "localhost", "127.0.0.1",
    "application/json", "utf-8", "content-type", "authorization",
    "node_modules", "package.json", "index.html", "description",
    "dependencies", "devdependencies", "repository", "license",
    "export default", "module.exports", "require"
}


def extract_candidates_from_line(line: str, line_number: int, rule_matches: list[dict] = None) -> list[Candidate]:
    """
    Extracts candidate secret strings and associated context from a single line.
    Includes any explicit rule matches and heuristic candidates.
    """
    candidates: list[Candidate] = []
    seen_values = set()

    # 1. First add candidates identified by rule matches
    if rule_matches:
        for rm in rule_matches:
            val = rm["candidate"]
            if val and val not in seen_values:
                seen_values.add(val)
                candidates.append(Candidate(
                    value=val,
                    context=rm.get("category", ""),
                    is_quoted='"' in line or "'" in line,
                    line_number=line_number,
                    rule_match=rm
                ))

    # 2. Extract assignment-style candidates
    for m in ASSIGNMENT_REGEX.finditer(line):
        key = m.group("key")
        val = m.group("val")
        is_quoted = bool(m.group("quote"))

        if val in seen_values or val.lower() in BENIGN_IGNORE_STRINGS:
            continue

        # Check if key is suspicious or value has sufficient entropy
        entropy = calculate_entropy(val)
        is_suspicious_key = bool(SUSPICIOUS_KEYWORD_REGEX.search(key))

        if is_suspicious_key or (entropy >= 3.0 and len(val) >= 16):
            seen_values.add(val)
            candidates.append(Candidate(
                value=val,
                context=key,
                is_quoted=is_quoted,
                line_number=line_number,
                rule_match=None
            ))

    # 3. Extract standalone high-entropy tokens if line has suspicious keywords
    if SUSPICIOUS_KEYWORD_REGEX.search(line):
        for m in STANDALONE_TOKEN_REGEX.finditer(line):
            val = m.group(1)
            if val in seen_values or val.lower() in BENIGN_IGNORE_STRINGS:
                continue
            entropy = calculate_entropy(val)
            if entropy >= 3.3 and len(val) >= 20:
                seen_values.add(val)
                candidates.append(Candidate(
                    value=val,
                    context=line[:m.start()].strip()[-30:],
                    is_quoted='"' in line or "'" in line,
                    line_number=line_number,
                    rule_match=None
                ))

    return candidates

