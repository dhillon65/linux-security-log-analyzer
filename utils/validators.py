"""
utils/validators.py

Validation functions
"""

import re

from config.settings import (
    IP_REGEX
)


def is_valid_ip(
    ip_address
):

    if not ip_address:

        return False

    if not re.fullmatch(
        IP_REGEX,
        ip_address
    ):

        return False

    try:

        parts = ip_address.split(
            "."
        )

        for part in parts:

            if (
                int(part) < 0
                or
                int(part) > 255
            ):

                return False

        return True

    except ValueError:

        return False


def is_valid_username(
    username
):

    if not username:

        return False

    pattern = (
        r"^[a-zA-Z0-9_-]{1,32}$"
    )

    return bool(

        re.match(
            pattern,
            username
        )

    )


def is_valid_severity(
    severity
):

    valid_levels = [

        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"

    ]

    return (
        severity
        in valid_levels
    )


def validate_log_record(
    record
):

    required_fields = [

        "timestamp",
        "event_type",
        "raw_log"

    ]

    for field in required_fields:

        if field not in record:

            return False

    return True


def validate_threat_record(
    record
):

    required_fields = [

        "ip",
        "score",
        "severity"

    ]

    for field in required_fields:

        if field not in record:

            return False

    if not is_valid_ip(
        record["ip"]
    ):

        return False

    if not is_valid_severity(
        record["severity"]
    ):

        return False

    return True