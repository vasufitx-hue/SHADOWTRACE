
import pytest

from backend.app.engines.scam_dna import (
    normalize_text,
    extract_indicators,
    classify_scam,
    create_scam_fingerprint,
    compare_scam_fingerprints
)


def test_normalize_text():
    assert normalize_text(" HELLO WORLD ") == "hello world"


def test_extract_indicators():
    result = extract_indicators("Your OTP is urgent!")
    assert result == ["otp", "urgent"]


def test_classify_scam():
    assert classify_scam("Your OTP is required") == "OTP Theft"


def test_create_scam_fingerprint():
    result = create_scam_fingerprint("Your OTP is required")

    assert result["category"] == "OTP Theft"
    assert result["indicator_count"] == 1


def test_compare_scam_fingerprints():
    result = compare_scam_fingerprints(
        "Your KYC is blocked",
        "Verify your KYC"
    )

    assert result["similarity"] == 0.33
