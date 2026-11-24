
import pytest

from backend.app.engines.risk_engine import (
    calculate_risk,
    classify_risk,
)


def test_classify_low_risk():
    assert classify_risk(10) == "LOW"


def test_classify_medium_risk():
    assert classify_risk(20) == "MEDIUM"


def test_classify_high_risk():
    assert classify_risk(40) == "HIGH"


def test_classify_critical_risk():
    assert classify_risk(70) == "CRITICAL"


def test_ip_address_increases_risk():
    result = calculate_risk(
        url_result={
            "indicators": [
                "IP address used as hostname"
            ]
        }
    )

    assert result["risk_score"] == 25
    assert result["risk_level"] == "MEDIUM"


def test_suspicious_keywords_increase_risk():
    result = calculate_risk(
        text_result={
            "detected_keywords": [
                "urgent",
                "bank account",
            ],
            "detected_urls": [],
        }
    )

    assert result["risk_score"] == 10


def test_score_never_exceeds_100():
    result = calculate_risk(
        text_result={
            "detected_keywords": [
                "urgent",
                "bank account",
                "otp",
                "password",
                "verify kyc",
                "click here",
            ],
            "detected_urls": [
                "http://example.invalid",
                "http://example.invalid/login",
                "http://example.invalid/verify",
            ],
        },
        url_result={
            "indicators": [
                "IP address used as hostname",
                "Known URL shortening service",
                "Punycode domain detected",
                "Credentials embedded in URL",
                "Unencrypted HTTP connection",
                "Suspicious path keyword: login",
            ]
        },
    )

    assert result["risk_score"] == 100


def test_rejects_missing_results():
    with pytest.raises(ValueError):
        calculate_risk()


def test_rejects_invalid_score():
    with pytest.raises(ValueError):
        classify_risk(150)


def test_rejects_invalid_analyzer_result():
    with pytest.raises(TypeError):
        calculate_risk(text_result="invalid")


def test_returns_explanation():
    result = calculate_risk(
        url_result={
            "indicators": [
                "Unencrypted HTTP connection"
            ]
        }
    )

    assert len(result["reasons"]) > 0
    assert "score_breakdown" in result
