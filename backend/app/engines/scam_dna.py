 
import re


SCAM_INDICATORS = [
    "otp",
    "kyc",
    "blocked",
    "urgent",
    "verify",
    "cashback",
    "suspended",
    "password",
    "refund",
    "upi"
]


def normalize_text(text):
    """Convert text into clean lowercase format."""

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    return text.lower().strip()


def extract_indicators(text):
    """Find suspicious indicators in a message."""

    cleaned_text = normalize_text(text)

    words = set(re.findall(r"[a-z0-9]+", cleaned_text))

    detected = []

    for indicator in SCAM_INDICATORS:
        if indicator in words:
            detected.append(indicator)

    return detected


def classify_scam(text):
    """Identify the likely scam category."""

    indicators = extract_indicators(text)

    if "otp" in indicators:
        return "OTP Theft"

    if "kyc" in indicators or "blocked" in indicators:
        return "Banking Phishing"

    if "cashback" in indicators or "refund" in indicators:
        return "Fake Reward or Refund"

    if "upi" in indicators:
        return "UPI Scam"

    if "password" in indicators:
        return "Credential Theft"

    return "Unknown"


def create_scam_fingerprint(text):
    """Generate a structured scam fingerprint."""

    cleaned_text = normalize_text(text)
    indicators = extract_indicators(cleaned_text)
    category = classify_scam(cleaned_text)

    return {
        "normalized_text": cleaned_text,
        "indicators": indicators,
        "category": category,
        "indicator_count": len(indicators)
    }


def compare_scam_fingerprints(message_a, message_b):
    """Compare two messages using Jaccard similarity."""

    fingerprint_a = create_scam_fingerprint(message_a)
    fingerprint_b = create_scam_fingerprint(message_b)

    indicators_a = set(fingerprint_a["indicators"])
    indicators_b = set(fingerprint_b["indicators"])

    common_indicators = indicators_a.intersection(indicators_b)
    all_indicators = indicators_a.union(indicators_b)

    if not all_indicators:
        similarity = 0.0
    else:
        similarity = len(common_indicators) / len(all_indicators)

    return {
        "common_indicators": sorted(common_indicators),
        "similarity": round(similarity, 2)
    }



if __name__ == "__main__":

    message = "URGENT! Your SBI account is blocked. Verify your KYC."

    print("\nDETECTED INDICATORS:")
    print(extract_indicators(message))

    print("\nSCAM CATEGORY:")
    print(classify_scam(message))

    print("\nSCAM FINGERPRINT:")
    print(create_scam_fingerprint(message))

    message_a = "Your bank account is blocked. Verify your KYC."
    message_b = "Urgent! Complete your KYC or account suspended."

    print("\nFINGERPRINT COMPARISON:")
    print(compare_scam_fingerprints(message_a, message_b))
