"""
analyzer/parser.py

Linux Authentication Log Parser

Supports:
- Failed SSH Logins
- Successful SSH Logins
- Root Logins
- Sudo Activity
"""

import re

from config.settings import (
    FAILED_LOGIN_REGEX,
    SUCCESS_LOGIN_REGEX,
    IP_REGEX,
    USERNAME_REGEX,
    EVENT_FAILED_LOGIN,
    EVENT_SUCCESS_LOGIN,
    EVENT_ROOT_LOGIN,
    EVENT_SUDO_USAGE
)


class LogParser:

    def __init__(self):

        self.records = []

    def parse(self, log_file):

        self.records = []

        with open(
            log_file,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line in file:

                parsed = self._parse_line(
                    line.strip()
                )

                if parsed:

                    self.records.append(
                        parsed
                    )

        return self.records

    def _parse_line(self, line):

        try:

            timestamp = self._extract_timestamp(
                line
            )

            service = self._extract_service(
                line
            )

            ip = self._extract_ip(
                line
            )

            username = (
                self._extract_username(
                    line
                )
            )

            event_type = (
                self._detect_event_type(
                    line
                )
            )

            if event_type is None:

                return None

            return {
                "timestamp": timestamp,
                "service": service,
                "ip": ip,
                "username": username,
                "event_type": event_type,
                "raw_log": line
            }

        except Exception:

            return None

    def _extract_timestamp(self, line):

        """
        Example:

        Jul 20 08:00:01
        """

        match = re.match(
            r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)",
            line
        )

        if match:

            return match.group(1)

        return "Unknown"

    def _extract_service(self, line):

        """
        Example:

        sshd[1234]
        sudo
        """

        match = re.search(
            r"([a-zA-Z0-9_-]+)\[\d+\]",
            line
        )

        if match:

            return match.group(1)

        if "sudo" in line:

            return "sudo"

        return "unknown"

    def _extract_ip(self, line):

        match = re.search(
            IP_REGEX,
            line
        )

        if match:

            return match.group()

        return None

    def _extract_username(self, line):

        match = re.search(
            USERNAME_REGEX,
            line
        )

        if match:

            return match.group(1)

        return None

    def _detect_event_type(self, line):

        if FAILED_LOGIN_REGEX in line:

            return EVENT_FAILED_LOGIN

        if SUCCESS_LOGIN_REGEX in line:

            return EVENT_SUCCESS_LOGIN

        if "sudo" in line.lower():

            return EVENT_SUDO_USAGE

        if (
            "Accepted password for root"
            in line
        ):

            return EVENT_ROOT_LOGIN

        return None

    def get_records(self):

        return self.records

    def count_records(self):

        return len(
            self.records
        )