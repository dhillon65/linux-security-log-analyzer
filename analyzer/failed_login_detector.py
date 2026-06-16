"""
analyzer/failed_login_detector.py

Detects and analyzes failed login attempts
from parsed Linux authentication logs.
"""

from collections import Counter

from config.settings import (
    EVENT_FAILED_LOGIN
)


class FailedLoginDetector:

    def __init__(self, records):

        self.records = records

        self.failed_logins = (
            self._extract_failed_logins()
        )

    def _extract_failed_logins(self):

        return [
            record
            for record in self.records
            if record.get("event_type")
            == EVENT_FAILED_LOGIN
        ]

    def get_failed_logins(self):

        return self.failed_logins

    def total_failed_logins(self):

        return len(
            self.failed_logins
        )

    def count_by_ip(self):

        counter = Counter()

        for record in self.failed_logins:

            ip = record.get("ip")

            if ip:

                counter[ip] += 1

        return dict(counter)

    def count_by_username(self):

        counter = Counter()

        for record in self.failed_logins:

            username = record.get(
                "username"
            )

            if username:

                counter[username] += 1

        return dict(counter)

    def get_top_attackers(
        self,
        limit=10
    ):

        ip_counts = (
            self.count_by_ip()
        )

        sorted_ips = sorted(
            ip_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return sorted_ips[:limit]

    def get_most_targeted_users(
        self,
        limit=10
    ):

        user_counts = (
            self.count_by_username()
        )

        sorted_users = sorted(
            user_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return sorted_users[:limit]

    def get_unique_attacker_count(
        self
    ):

        ips = {
            record["ip"]
            for record in self.failed_logins
            if record.get("ip")
        }

        return len(ips)

    def generate_summary(self):

        return {

            "total_failed_logins":
            self.total_failed_logins(),

            "unique_attacker_ips":
            self.get_unique_attacker_count(),

            "top_attackers":
            self.get_top_attackers(),

            "targeted_users":
            self.get_most_targeted_users()
        }

    def print_summary(self):

        summary = (
            self.generate_summary()
        )

        print(
            "\nFAILED LOGIN SUMMARY"
        )

        print(
            "-" * 40
        )

        print(
            f"Total Failed Logins: "
            f"{summary['total_failed_logins']}"
        )

        print(
            f"Unique Attacker IPs: "
            f"{summary['unique_attacker_ips']}"
        )

        print(
            "\nTop Attacker IPs"
        )

        for ip, count in (
            summary["top_attackers"]
        ):

            print(
                f"{ip} -> {count}"
            )

        print(
            "\nMost Targeted Users"
        )

        for user, count in (
            summary["targeted_users"]
        ):

            print(
                f"{user} -> {count}"
            )