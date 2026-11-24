
"""Rule-based risk scoring engine for SHADOWTRACE."""

TEXT_KEYWORD_WEIGHT = 5
TEXT_KEYWORD_CAP = 25

URL_WEIGHT = 5
URL_CAP = 10

INDICATOR_WEIGHTS = {
    "IP address used as hostname": 25,
    "Known URL shortening service": 15,
    "Punycode domain detected": 25,
    "Credentials embedded in URL": 30,
    "Unencrypted HTTP connection": 10,
}


def validate_result(result: dict, field: str) -> list:
    """Validate an analyzer result and return its indicator list."""

    if not isinstance(result, dict):
        raise TypeError("Analyzer result must be a dictionary.")

    indicators = result.get(field, [])

    if not isinstance(indicators, list):
        raise TypeError(f"{field} must be a list.")

    if not all(isinstance(item, str) for item in indicators):
        raise TypeError(f"Every item in {field} must be a string.")

    return indicators


def classify_risk(score: int) -> str:
    """Convert a numerical score into a risk category."""

    if not isinstance(score, int) or isinstance(score, bool):
        raise TypeError("Risk score must be an integer.")

    if not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100.")

    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"

    return "LOW"


def calculate_risk(
    text_result: dict | None = None,
    url_result: dict | None = None,
) -> dict:
    """Calculate an explainable risk score from analyzer results."""

    if text_result is None and url_result is None:
        raise ValueError("At least one analyzer result is required.")

    score = 0
    reasons = []
    breakdown = {}

    if text_result is not None:
        keywords = validate_result(
            text_result,
            "detected_keywords"
        )

        keyword_points = min(
            len(keywords) * TEXT_KEYWORD_WEIGHT,
            TEXT_KEYWORD_CAP
        )

        breakdown["text_keywords"] = keyword_points

        if keyword_points:
            score += keyword_points
            reasons.append(
                f"Suspicious text keywords detected: {len(keywords)}"
            )

        urls = validate_result(text_result, "detected_urls")

        url_points = min(
            len(urls) * URL_WEIGHT,
            URL_CAP
        )

        breakdown["text_urls"] = url_points

        if url_points:
            score += url_points
            reasons.append(
                f"URLs found in message: {len(urls)}"
            )

    if url_result is not None:
        indicators = validate_result(url_result, "indicators")

        indicator_points = 0

        for indicator in indicators:
            if indicator in INDICATOR_WEIGHTS:
                points = INDICATOR_WEIGHTS[indicator]
            elif indicator.startswith("Suspicious path keyword: "):
                points = 8
            else:
                points = 0

            indicator_points += points

            if points:
                reasons.append(
                    f"{indicator} (+{points})"
                )

      
        indicator_points = min(indicator_points, 75)

        breakdown["url_indicators"] = indicator_points
        score += indicator_points

    score = min(score, 100)

    return {
        "risk_score": score,
        "risk_level": classify_risk(score),
        "reasons": reasons,
        "score_breakdown": breakdown,
    }
