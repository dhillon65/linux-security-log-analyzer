"""
analyzer/success_login_detector.py

Analyzes successful login activity
from Linux authentication logs.
"""

from collections import Counter

from config.settings import (
    EVENT_SUCCESS_LOGIN,
    EVENT_ROOT_LOGIN
)


class SuccessLoginDetector:

    def __init__(self, records):

        self.records = records

        self.successful_logins = (
            self._extract_successful_logins()
        )

    def _extract_successful_logins(self):

        return [

            record

            for record in self.records

            if record.get("event_type")
            in (
                EVENT_SUCCESS_LOGIN,
                EVENT_ROOT_LOGIN
            )

        ]

    def get_successful_logins(self):

        return self.successful_logins

    def total_successful_logins(self):

        return len(
            self.successful_logins
        )

    def count_by_user(self):

        counter = Counter()

        for record in self.successful_logins:

            username = record.get(
                "username"
            )

            if username:

                counter[username] += 1

        return dict(counter)

    def count_by_ip(self):

        counter = Counter()

        for record in self.successful_logins:

            ip = record.get("ip")

            if ip:

                counter[ip] += 1

        return dict(counter)

    def get_active_users(
        self,
        limit=10
    ):

        user_counts = (
            self.count_by_user()
        )

        sorted_users = sorted(

            user_counts.items(),

            key=lambda x: x[1],

            reverse=True

        )

        return sorted_users[:limit]

    def get_active_ips(
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

    def get_root_logins(self):

        return [

            record

            for record in self.successful_logins

            if record.get("username")
            == "root"

        ]

    def root_login_count(self):

        return len(
            self.get_root_logins()
        )

    def unique_users(self):

        users = {

            record["username"]

            for record in self.successful_logins

            if record.get("username")

        }

        return len(users)

    def unique_ips(self):

        ips = {

            record["ip"]

            for record in self.successful_logins

            if record.get("ip")

        }

        return len(ips)

    def generate_summary(self):

        return {

            "total_successful_logins":
            self.total_successful_logins(),

            "unique_users":
            self.unique_users(),

            "unique_ips":
            self.unique_ips(),

            "root_logins":
            self.root_login_count(),

            "top_users":
            self.get_active_users(),

            "top_ips":
            self.get_active_ips()

        }

    def print_summary(self):

        summary = (
            self.generate_summary()
        )

        print(
            "\nSUCCESSFUL LOGIN SUMMARY"
        )

        print(
            "-" * 50
        )

        print(
            f"Total Successful Logins : "
            f"{summary['total_successful_logins']}"
        )

        print(
            f"Unique Users            : "
            f"{summary['unique_users']}"
        )

        print(
            f"Unique IPs              : "
            f"{summary['unique_ips']}"
        )

        print(
            f"Root Logins             : "
            f"{summary['root_logins']}"
        )

        print(
            "\nMost Active Users"
        )

        for user, count in (
            summary["top_users"]
        ):

            print(
                f"{user} -> {count}"
            )

        print(
            "\nMost Active IPs"
        )

        for ip, count in (
            summary["top_ips"]
        ):

            print(
                f"{ip} -> {count}"
            )