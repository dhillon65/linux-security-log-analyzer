import csv
from pathlib import Path


class CSVGenerator:

    def generate(
        self,
        results,
        output_file
    ):

        Path(output_file).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        threats = results.get(
            "threat_scores",
            []
        )

        with open(
            output_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as csvfile:

            writer = csv.writer(
                csvfile
            )

            writer.writerow([
                "IP Address",
                "Score",
                "Severity"
            ])

            for item in threats:

                writer.writerow([
                    item["ip"],
                    item["score"],
                    item["severity"]
                ])

        return output_file