"""
analyzer/brute_force_detector.py

Brute Force Attack Detection Engine

Detects repeated failed login attempts
from the same source IP.
"""

from collections import Counter

from config.settings import (
    BRUTE_FORCE_THRESHOLD,
    LOW_THRESHOLD,
    MEDIUM_THRESHOLD,
    HIGH_THRESHOLD,
    EVENT_FAILED_LOGIN
)


class BruteForceDetector:

    def __init__(self, records):

        self.records = records

        self.failed_records = (
            self._get_failed_records()
        )

    def _get_failed_records(self):

        return [

            record

            for record in self.records

            if record.get("event_type")
            == EVENT_FAILED_LOGIN

        ]

    def count_attempts_per_ip(self):

        counter = Counter()

        for record in self.failed_records:

            ip = record.get("ip")

            if ip:

                counter[ip] += 1

        return dict(counter)

    def calculate_severity(
        self,
        attempts
    ):

        if attempts >= HIGH_THRESHOLD:

            return "CRITICAL"

        elif attempts >= MEDIUM_THRESHOLD:

            return "HIGH"

        elif attempts >= LOW_THRESHOLD:

            return "MEDIUM"

        else:

            return "LOW"

    def detect(self):

        alerts = []

        ip_counts = (
            self.count_attempts_per_ip()
        )

        for ip, attempts in (
            ip_counts.items()
        ):

            if (
                attempts >=
                BRUTE_FORCE_THRESHOLD
            ):

                severity = (
                    self.calculate_severity(
                        attempts
                    )
                )

                alerts.append({

                    "ip": ip,

                    "attempts": attempts,

                    "severity": severity,

                    "alert_type":
                    "BRUTE_FORCE"

                })

        alerts.sort(

            key=lambda x:
            x["attempts"],

            reverse=True

        )

        return alerts

    def get_critical_alerts(self):

        alerts = self.detect()

        return [

            alert

            for alert in alerts

            if alert["severity"]
            == "CRITICAL"

        ]

    def get_high_alerts(self):

        alerts = self.detect()

        return [

            alert

            for alert in alerts

            if alert["severity"]
            == "HIGH"

        ]

    def get_medium_alerts(self):

        alerts = self.detect()

        return [

            alert

            for alert in alerts

            if alert["severity"]
            == "MEDIUM"

        ]

    def total_alerts(self):

        return len(
            self.detect()
        )

    def generate_summary(self):

        alerts = self.detect()

        return {

            "total_alerts":
            len(alerts),

            "critical":
            len(
                self.get_critical_alerts()
            ),

            "high":
            len(
                self.get_high_alerts()
            ),

            "medium":
            len(
                self.get_medium_alerts()
            ),

            "alerts":
            alerts

        }

    def print_summary(self):

        summary = (
            self.generate_summary()
        )

        print(
            "\nBRUTE FORCE ANALYSIS"
        )

        print(
            "-" * 60
        )

        print(
            f"Total Alerts : "
            f"{summary['total_alerts']}"
        )

        print(
            f"Critical     : "
            f"{summary['critical']}"
        )

        print(
            f"High         : "
            f"{summary['high']}"
        )

        print(
            f"Medium       : "
            f"{summary['medium']}"
        )

        print(
            "\nDetected Attackers"
        )

        print(
            "-" * 60
        )

        for alert in (
            summary["alerts"]
        ):

            print(

                f"IP: "
                f"{alert['ip']} | "

                f"Attempts: "
                f"{alert['attempts']} | "

                f"Severity: "
                f"{alert['severity']}"

            )