

def format_intelligence_report(result):
    """
    Convert SHADOWTRACE analysis results
    into a readable security report.
    """

    risk = result["risk_analysis"]
    text = result["text_analysis"]
    scam_dna = result["scam_dna"]
    urls = result["url_analysis"]

    report = []

    report.append("=" * 55)
    report.append("             SHADOWTRACE INTELLIGENCE REPORT")
    report.append("=" * 55)

    report.append(f"\nMESSAGE:\n{result['message']}")

    report.append("\n--- TEXT ANALYSIS ---")
    report.append(
        f"Suspicious keywords: {text['detected_keywords']}"
    )
    report.append(
        f"Extracted URLs: {text['detected_urls']}"
    )

    report.append("\n--- SCAM DNA ---")
    report.append(
        f"Likely category: {scam_dna['category']}"
    )
    report.append(
        f"Indicators: {scam_dna['indicators']}"
    )

    report.append("\n--- URL INTELLIGENCE ---")

    if urls:
        for url in urls:
            report.append(f"Hostname: {url['hostname']}")
            report.append(f"Indicators: {url['indicators']}")
    else:
        report.append("No URLs detected.")

    report.append("\n--- RISK ASSESSMENT ---")
    report.append(f"Risk score: {risk['risk_score']}/100")
    report.append(f"Risk level: {risk['risk_level']}")

    report.append("\nRisk reasons:")

    if risk["reasons"]:
        for reason in risk["reasons"]:
            report.append(f"- {reason}")
    else:
        report.append("- No risk indicators contributed to the score.")

    report.append("\n" + "=" * 55)

    return "\n".join(report)
