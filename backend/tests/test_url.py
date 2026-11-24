
import pytest

from backend.app.engines.url_analyzer import analyze_url


def test_detects_ip_address():
    result = analyze_url("http://192.0.2.1/login")

    assert "IP address used as hostname" in result["indicators"]


def test_detects_url_shortener():
    result = analyze_url("https://bit.ly/example")

    assert "Known URL shortening service" in result["indicators"]


def test_detects_http():
    result = analyze_url("http://example.com")

    assert "Unencrypted HTTP connection" in result["indicators"]


def test_detects_punycode():
    result = analyze_url("https://xn--pple-43d.com")

    assert "Punycode domain detected" in result["indicators"]


def test_detects_suspicious_path():
    result = analyze_url("https://example.com/bank/login")

    assert any(
        item.startswith("Suspicious path keyword:")
        for item in result["indicators"]
    )


def test_rejects_empty_url():
    with pytest.raises(ValueError):
        analyze_url("")


def test_rejects_non_string_url():
    with pytest.raises(TypeError):
        analyze_url(123)
