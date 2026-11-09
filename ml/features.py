import re
import math
from collections import Counter

# Known secret/token prefixes (without containing real credentials)
KNOWN_PREFIXES = (
    "akia", "asia", "abia", "acca", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "github_pat_", "sk_live_", "pk_live_", "rk_live_", "xoxb-", "xoxp-",
    "xapp-", "eyj", "sq0atp-", "key-", "secret-"
)

# Suspicious context keywords with assigned weights
CONTEXT_KEYWORDS = {
    "secret": 3.0,
    "token": 2.5,
    "password": 3.0,
    "passwd": 2.5,
    "api_key": 3.0,
    "apikey": 3.0,
    "access_key": 2.5,
    "client_secret": 3.0,
    "auth": 2.0,
    "bearer": 2.0,
    "credential": 2.5,
    "private_key": 3.0,
    "connection": 1.5,
    "db_pass": 2.5,
    "key": 1.0,
}

FEATURE_NAMES = [
    "length",
    "entropy",
    "uppercase_ratio",
    "lowercase_ratio",
    "digit_ratio",
    "special_ratio",
    "unique_char_ratio",
    "has_uppercase",
    "has_lowercase",
    "has_digits",
    "has_special_chars",
    "has_known_prefix",
    "context_keyword_score",
    "is_quoted_value"
]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of the string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 4)


def calculate_context_keyword_score(context: str) -> float:
    """Calculates a small numeric score based on contextual keywords."""
    if not context:
        return 0.0
    ctx_lower = context.lower()
    score = 0.0
    for keyword, weight in CONTEXT_KEYWORDS.items():
        if keyword in ctx_lower:
            score += weight
    return min(score, 10.0)


def extract_features(candidate: str, context: str = "", is_quoted: bool = False) -> list[float]:
    """
    Extracts the 14 mandatory numeric features from a candidate string and context.
    Returns a list of float values matching FEATURE_NAMES.
    """
    text = candidate or ""
    length = len(text)

    if length == 0:
        return [0.0] * len(FEATURE_NAMES)

    upper_count = sum(1 for c in text if c.isupper())
    lower_count = sum(1 for c in text if c.islower())
    digit_count = sum(1 for c in text if c.isdigit())
    special_count = sum(1 for c in text if not c.isalnum())
    unique_count = len(set(text))

    text_lower = text.lower()
    has_known_prefix = 1.0 if any(text_lower.startswith(p) for p in KNOWN_PREFIXES) else 0.0

    features = [
        float(length),
        calculate_entropy(text),
        round(upper_count / length, 4),
        round(lower_count / length, 4),
        round(digit_count / length, 4),
        round(special_count / length, 4),
        round(unique_count / length, 4),
        1.0 if upper_count > 0 else 0.0,
        1.0 if lower_count > 0 else 0.0,
        1.0 if digit_count > 0 else 0.0,
        1.0 if special_count > 0 else 0.0,
        has_known_prefix,
        calculate_context_keyword_score(context),
        1.0 if is_quoted else 0.0,
    ]

    return features
