
from fastapi.testclient import TestClient

from backend.app.api import app


client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "status": "online",
        "project": "SHADOWTRACE"
    }


def test_analyze_endpoint():
    response = client.post(
        "/analyze",
        json={
            "message": (
                "URGENT! Your bank account is blocked. "
                "Verify your KYC at http://fake-bank.example/login"
            )
        }
    )

    assert response.status_code == 200

    result = response.json()

    assert "text_analysis" in result
    assert "url_analysis" in result
    assert "scam_dna" in result
    assert "risk_analysis" in result


def test_analyze_empty_message():
    response = client.post(
        "/analyze",
        json={"message": ""}
    )

    assert response.status_code == 422

def test_rejects_whitespace_message():
    response = client.post(
        "/analyze",
        json={"message": "     "}
    )

    assert response.status_code == 422


def test_rejects_missing_message():
    response = client.post(
        "/analyze",
        json={}
    )

    assert response.status_code == 422


def test_rejects_non_string_message():
    response = client.post(
        "/analyze",
        json={"message": 123}
    )

    assert response.status_code == 422

def test_rejects_message_over_5000_characters():
    long_message = "A" * 5001

    response = client.post(
        "/analyze",
        json={"message": long_message}
    )

    assert response.status_code == 422
def test_cors_allows_frontend_origin():
    response = client.options(
        "/analyze",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }
    )

    assert response.status_code == 200

    assert response.headers["access-control-allow-origin"] == (
        "http://localhost:3000"
    )

    assert "POST" in response.headers["access-control-allow-methods"]