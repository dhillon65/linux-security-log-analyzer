"""
utils/logger.py

Centralized logging module
"""

import logging

from config.settings import (
    LOG_LEVEL,
    LOG_FILE
)


def get_logger():

    logger = logging.getLogger(
        "LinuxLogAnalyzer"
    )

    if logger.handlers:
        return logger

    logger.setLevel(LOG_LEVEL)

    formatter = logging.Formatter(

        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"

    )

    file_handler = logging.FileHandler(
        LOG_FILE
    )

    file_handler.setFormatter(
        formatter
    )

    console_handler = (
        logging.StreamHandler()
    )

    console_handler.setFormatter(
        formatter
    )

    logger.addHandler(
        file_handler
    )

    logger.addHandler(
        console_handler
    )

    return logger