import math


def calculate_statistics(numbers: list[float]) -> dict:
    """Calculates basic statistics for a list of numbers."""
    if not numbers:
        return {"count": 0, "mean": 0.0, "variance": 0.0}

    count = len(numbers)
    mean = sum(numbers) / count
    variance = sum((x - mean) ** 2 for x in numbers) / count

    return {
        "count": count,
        "mean": round(mean, 4),
        "variance": round(variance, 4),
        "std_dev": round(math.sqrt(variance), 4)
    }


def normalize_text(text: str) -> str:
    """Sanitizes and normalizes user input text."""
    if not text:
        return ""
    return " ".join(text.strip().split())

