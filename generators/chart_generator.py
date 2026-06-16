from pathlib import Path

import matplotlib.pyplot as plt

from config.settings import (
    CHART_DIR
)


class ChartGenerator:

    def generate(
        self,
        results
    ):

        Path(CHART_DIR).mkdir(
            parents=True,
            exist_ok=True
        )

        self.generate_top_attackers(
            results
        )

        self.generate_severity_chart(
            results
        )

    def generate_top_attackers(
        self,
        results
    ):

        data = results.get(
            "suspicious_ips",
            []
        )[:10]

        if not data:
            return

        ips = [
            item["ip"]
            for item in data
        ]

        scores = [
            item["score"]
            for item in data
        ]

        plt.figure(
            figsize=(10, 6)
        )

        plt.barh(
            ips,
            scores
        )

        plt.title(
            "Top Suspicious IPs"
        )

        plt.xlabel(
            "Threat Score"
        )

        plt.tight_layout()

        plt.savefig(
            Path(CHART_DIR)
            / "top_attackers.png"
        )

        plt.close()

    def generate_severity_chart(
        self,
        results
    ):

        threats = results.get(
            "threat_scores",
            []
        )

        severity_count = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for item in threats:

            sev = item["severity"]

            severity_count[sev] += 1

        plt.figure(
            figsize=(8, 6)
        )

        plt.pie(
            severity_count.values(),
            labels=severity_count.keys(),
            autopct="%1.1f%%"
        )

        plt.title(
            "Threat Severity Distribution"
        )

        plt.savefig(
            Path(CHART_DIR)
            / "severity_distribution.png"
        )

        plt.close()