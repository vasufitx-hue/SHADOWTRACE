
import json

from backend.app.report_exporter import export_report


def test_export_report_creates_json_file(tmp_path):
    sample_result = {
        "message": "URGENT! Verify your KYC.",
        "risk_analysis": {
            "risk_score": 25,
            "risk_level": "MEDIUM"
        }
    }

    file_path = tmp_path / "test_report.json"

    export_report(sample_result, file_path)

    assert file_path.exists()

    with file_path.open("r", encoding="utf-8") as file:
        saved_data = json.load(file)

    assert saved_data == sample_result
