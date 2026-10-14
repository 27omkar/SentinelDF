import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte."""
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def analyze_file(path: str):
    """Analyze a file's byte entropy without modifying it."""
    try:
        with open(path, "rb") as file:
            data = file.read()

        entropy = shannon_entropy(data)

        return {
            "entropy": round(entropy, 3),
            "size_bytes": len(data),
            "high_entropy": entropy >= 7.2,
            "status": (
                "High entropy — review"
                if entropy >= 7.2
                else "No high-entropy signal"
            )
        }

    except (OSError, PermissionError) as error:
        return {
            "entropy": None,
            "size_bytes": None,
            "high_entropy": False,
            "status": f"Unable to read file: {error}"
        }