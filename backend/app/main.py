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

    
    text_result = analyze_text(message)

    
    url_results = []

    for url in text_result["detected_urls"]:
        url_result = analyze_url(url)
        url_results.append(url_result)

    
    combined_indicators = []

    for result in url_results:
        combined_indicators.extend(result["indicators"])

    url_risk_input = (
        {"indicators": combined_indicators}
        if url_results
        else None
    )

    
    risk_result = calculate_risk(
        text_result=text_result,
        url_result=url_risk_input,
    )


    scam_dna_result = {
        "indicators": extract_indicators(message),
        "category": classify_scam(message),
        "fingerprint": create_scam_fingerprint(message),
    }

    
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
        "Verify your KYC immediately at "
        "http://fake-bank.example/login"
    )

    result = analyze_scam_message(message)
    

    print("\n========== SHADOWTRACE INTELLIGENCE REPORT ==========")

    print(format_intelligence_report(result))
    export_report(result)
print("\nJSON report exported successfully!")