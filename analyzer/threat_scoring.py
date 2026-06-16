"""
analyzer/threat_scoring.py

Threat Scoring Engine

Calculates security risk scores
for attacker IP addresses.
"""

from collections import defaultdict

from config.settings import (
    FAILED_LOGIN_WEIGHT,
    BRUTE_FORCE_WEIGHT,
    ROOT_LOGIN_WEIGHT,
    SUDO_WEIGHT
)


class ThreatScorer:

    def __init__(
        self,
        failed_logins,
        brute_force_alerts,
        root_logins=None,
        sudo_events=None
    ):

        self.failed_logins = (
            failed_logins or []
        )

        self.brute_force_alerts = (
            brute_force_alerts or []
        )

        self.root_logins = (
            root_logins or []
        )

        self.sudo_events = (
            sudo_events or []
        )

    def calculate(self):

        scores = defaultdict(int)

        self._score_failed_logins(
            scores
        )

        self._score_bruteforce(
            scores
        )

        self._score_root_logins(
            scores
        )

        self._score_sudo_activity(
            scores
        )

        return self._format_scores(
            scores
        )

    def _score_failed_logins(
        self,
        scores
    ):

        for record in (
            self.failed_logins
        ):

            ip = record.get("ip")

            if ip:

                scores[ip] += (
                    FAILED_LOGIN_WEIGHT
                )

    def _score_bruteforce(
        self,
        scores
    ):

        for alert in (
            self.brute_force_alerts
        ):

            ip = alert.get("ip")

            if ip:

                scores[ip] += (
                    BRUTE_FORCE_WEIGHT
                )

    def _score_root_logins(
        self,
        scores
    ):

        for record in (
            self.root_logins
        ):

            ip = record.get("ip")

            if ip:

                scores[ip] += (
                    ROOT_LOGIN_WEIGHT
                )

    def _score_sudo_activity(
        self,
        scores
    ):

        for record in (
            self.sudo_events
        ):

            ip = record.get("ip")

            if ip:

                scores[ip] += (
                    SUDO_WEIGHT
                )

    def determine_severity(
        self,
        score
    ):

        if score >= 100:

            return "CRITICAL"

        elif score >= 60:

            return "HIGH"

        elif score >= 30:

            return "MEDIUM"

        else:

            return "LOW"

    def _format_scores(
        self,
        scores
    ):

        results = []

        for ip, score in (
            scores.items()
        ):

            results.append({

                "ip": ip,

                "score": score,

                "severity":
                self.determine_severity(
                    score
                )

            })

        results.sort(

            key=lambda x:
            x["score"],

            reverse=True

        )

        return results

    def get_critical(
        self,
        scores
    ):

        return [

            item

            for item in scores

            if item["severity"]
            == "CRITICAL"

        ]

    def get_high(
        self,
        scores
    ):

        return [

            item

            for item in scores

            if item["severity"]
            == "HIGH"

        ]

    def get_medium(
        self,
        scores
    ):

        return [

            item

            for item in scores

            if item["severity"]
            == "MEDIUM"

        ]

    def get_low(
        self,
        scores
    ):

        return [

            item

            for item in scores

            if item["severity"]
            == "LOW"

        ]

    def generate_summary(
        self,
        scores
    ):

        return {

            "critical":
            len(
                self.get_critical(
                    scores
                )
            ),

            "high":
            len(
                self.get_high(
                    scores
                )
            ),

            "medium":
            len(
                self.get_medium(
                    scores
                )
            ),

            "low":
            len(
                self.get_low(
                    scores
                )
            ),

            "total":
            len(scores)

        }

    def print_summary(
        self,
        scores
    ):

        summary = (
            self.generate_summary(
                scores
            )
        )

        print(
            "\nTHREAT SCORE SUMMARY"
        )

        print(
            "-" * 60
        )

        print(
            f"Critical : "
            f"{summary['critical']}"
        )

        print(
            f"High     : "
            f"{summary['high']}"
        )

        print(
            f"Medium   : "
            f"{summary['medium']}"
        )

        print(
            f"Low      : "
            f"{summary['low']}"
        )

        print(
            "\nTop Threats"
        )

        print(
            "-" * 60
        )

        for item in scores[:10]:

            print(

                f"IP: {item['ip']} | "

                f"Score: {item['score']} | "

                f"Severity: "
                f"{item['severity']}"

            )