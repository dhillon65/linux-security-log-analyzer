import tempfile

from generators.csv_generator import (
    CSVGenerator
)


def test_csv_report_creation():

    results = {
        "threat_scores": [
            {
                "ip": "192.168.1.100",
                "score": 50,
                "severity": "HIGH"
            }
        ]
    }

    with tempfile.NamedTemporaryFile(
        suffix=".csv"
    ) as tmp:

        CSVGenerator().generate(
            results,
            tmp.name
        )

        with open(tmp.name) as f:

            content = f.read()

            assert (
                "192.168.1.100"
                in content
            )