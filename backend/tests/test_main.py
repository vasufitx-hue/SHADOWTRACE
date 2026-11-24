
import pytest

from backend.app.main import analyze_scam_message


def test_pipeline_returns_all_sections():
    message = "Your account is blocked. Verify KYC."

    result = analyze_scam_message(message)

    assert "text_analysis" in result
    assert "url_analysis" in result
    assert "scam_dna" in result
    assert "risk_analysis" in result


def test_pipeline_detects_scam_indicators():
    message = "URGENT! Your OTP is required."

    result = analyze_scam_message(message)

    assert "otp" in result["scam_dna"]["indicators"]
    assert result["scam_dna"]["category"] == "OTP Theft"


def test_pipeline_analyzes_extracted_urls():
    message = "Verify your bank account at http://example.com/login"

    result = analyze_scam_message(message)

    assert len(result["url_analysis"]) == 1

    url_result = result["url_analysis"][0]

    assert url_result["hostname"] == "example.com"
    assert "Unencrypted HTTP connection" in url_result["indicators"]


def test_pipeline_calculates_risk():
    message = "URGENT! Your bank account is blocked. Verify KYC."

    result = analyze_scam_message(message)

    assert isinstance(result["risk_analysis"]["risk_score"], int)
    assert 0 <= result["risk_analysis"]["risk_score"] <= 100

    assert result["risk_analysis"]["risk_level"] in [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]


def test_pipeline_rejects_empty_message():
    with pytest.raises(ValueError):
        analyze_scam_message("")
