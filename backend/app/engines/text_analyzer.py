
import re

SCAM_KEYWORDS = [
    "urgent",
    "account blocked",
    "verify kyc",
    "bank account",
    "click here",
    "claim reward",
    "otp",
    "password",
    "send money",
    "limited time",
]

def normalize_text(text: str) -> str:
    """Convert text into a consistent lowercase format."""

    return text.lower().strip()


def detect_scam_keywords(text: str) -> list[str]:
    """Find scam-related keywords in a message."""

    normalized_text = normalize_text(text)

    detected_keywords = []

    for keyword in SCAM_KEYWORDS:
        if keyword in normalized_text:
            detected_keywords.append(keyword)

    return detected_keywords


def extract_urls(text: str) -> list[str]:
    """Extract HTTP and HTTPS URLs from text."""

    pattern = r"https?://[^\s]+"

    urls = re.findall(pattern, text)

    return urls


def analyze_text(text: str) -> dict:
    """Analyze a message and return intelligence results."""

    if not isinstance(text, str):
        raise TypeError("Message must be a string.")

    if not text.strip():
        raise ValueError("Message cannot be empty.")

    keywords = detect_scam_keywords(text)
    urls = extract_urls(text)

    return {
        "message": text,
        "detected_keywords": keywords,
        "detected_urls": urls,
        "keyword_count": len(keywords),
        "url_count": len(urls),
    }
