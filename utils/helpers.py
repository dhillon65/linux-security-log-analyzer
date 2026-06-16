"""
utils/helpers.py

Helper functions used across project
"""

from datetime import datetime


def current_timestamp():

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def safe_division(
    numerator,
    denominator
):

    if denominator == 0:

        return 0

    return (
        numerator / denominator
    )


def percentage(
    part,
    total
):

    if total == 0:

        return 0

    return round(

        (part / total) * 100,

        2

    )


def sort_descending(
    data,
    key_name
):

    return sorted(

        data,

        key=lambda x:
        x[key_name],

        reverse=True

    )


def get_top_items(
    data,
    limit=10
):

    return data[:limit]


def severity_color(
    severity
):

    mapping = {

        "LOW":
        "#4CAF50",

        "MEDIUM":
        "#FFC107",

        "HIGH":
        "#FF5722",

        "CRITICAL":
        "#F44336"

    }

    return mapping.get(
        severity,
        "#9E9E9E"
    )