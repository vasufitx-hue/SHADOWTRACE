
from backend.app.report_exporter import export_report
from backend.app.engines.text_analyzer import analyze_text
from backend.app.engines.url_analyzer import analyze_url
from backend.app.engines.risk_engine import calculate_risk

from backend.app.engines.scam_dna import (
    extract_indicators,
    classify_scam,
    create_scam_fingerprint,
)

from backend.app.report_formatter import format_intelligence_report


def analyze_scam_message(message):
    """
    Analyze a suspicious message using all SHADOWTRACE engines.
    """

    if not isinstance(message, str) or not message.strip():
        raise ValueError("Message cannot be empty.")

    # 1. Analyze message text.
    text_result = analyze_text(message)

    # 2. Extract and analyze URLs.
    url_results = []

    for url in text_result["detected_urls"]:
        url_result = analyze_url(url)
        url_results.append(url_result)

    # 3. Combine URL indicators.
    combined_indicators = []

    for result in url_results:
        combined_indicators.extend(result["indicators"])

    url_risk_input = (
        {"indicators": combined_indicators}
        if url_results
        else None
    )

    # 4. Generate Scam DNA.
    scam_dna_result = {
        "indicators": extract_indicators(message),
        "category": classify_scam(message),
        "fingerprint": create_scam_fingerprint(message),
    }

    # 5. Calculate risk using all analyzer results.
    risk_result = calculate_risk(
        text_result=text_result,
        url_result=url_risk_input,
        scam_dna_result=scam_dna_result,
    )

    # 6. Return complete intelligence report.
    return {
        "message": message,
        "text_analysis": text_result,
        "url_analysis": url_results,
        "scam_dna": scam_dna_result,
        "risk_analysis": risk_result,
    }


if __name__ == "__main__":

    message = (
        "URGENT! Your SBI bank account is blocked. "
        "Verify your KYC immediately."
    )

    result = analyze_scam_message(message)

    print("\nSHADOWTRACE INTELLIGENCE REPORT")
    print(result)
