
from backend.app.engines.text_analyzer import analyze_text


def test_detects_scam_keywords():
    message = "URGENT! Verify KYC or your bank account will be blocked."

    result = analyze_text(message)

    assert "urgent" in result["detected_keywords"]
    assert "verify kyc" in result["detected_keywords"]

def test_extracts_urls():
    message = "Visit http://example.invalid/verify"

    result = analyze_text(message)

    assert "http://example.invalid/verify" in result["detected_urls"]

def test_rejects_empty_message():
    try:
        analyze_text("")

        assert False, "Expected ValueError"

    except ValueError:
        assert True
