import json
from pathlib import Path


def export_report(result, filename="intelligence_report.json"):
    """Export SHADOWTRACE results into a JSON file."""

    output_path = Path(filename)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            result,
            file,
            indent=4,
            ensure_ascii=False
        )

    return output_path