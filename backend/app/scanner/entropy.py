import math
from collections import Counter


def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon entropy of a string.
    Higher values indicate greater randomness / unpredictability.
    """
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)

