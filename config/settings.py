from pathlib import Path

# =====================================================
# PROJECT ROOT
# =====================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# =====================================================
# LOG FILES
# =====================================================

AUTH_LOG_FILE = (
    BASE_DIR /
    "data" /
    "sample_auth.log"
)

SYSLOG_FILE = (
    BASE_DIR /
    "data" /
    "sample_syslog.log"
)


# =====================================================
# REPORT DIRECTORIES
# =====================================================

REPORT_DIR = (
    BASE_DIR /
    "reports"
)

CSV_DIR = (
    REPORT_DIR /
    "csv"
)

JSON_DIR = (
    REPORT_DIR /
    "json"
)

PDF_DIR = (
    REPORT_DIR /
    "pdf"
)

CHART_DIR = (
    REPORT_DIR /
    "charts"
)


# =====================================================
# REPORT FILES
# =====================================================

CSV_REPORT_PATH = (
    CSV_DIR /
    "security_report.csv"
)

JSON_REPORT_PATH = (
    JSON_DIR /
    "security_report.json"
)

PDF_REPORT_PATH = (
    PDF_DIR /
    "security_report.pdf"
)


# =====================================================
# DETECTION SETTINGS
# =====================================================

# Number of failed attempts
# before brute force alert

BRUTE_FORCE_THRESHOLD = 5


# =====================================================
# THREAT SCORING
# =====================================================

FAILED_LOGIN_WEIGHT = 5

BRUTE_FORCE_WEIGHT = 20

ROOT_LOGIN_WEIGHT = 15

SUDO_WEIGHT = 10


# =====================================================
# SEVERITY LEVELS
# =====================================================

LOW_THRESHOLD = 20

MEDIUM_THRESHOLD = 50

HIGH_THRESHOLD = 80


# =====================================================
# CHART SETTINGS
# =====================================================

TOP_ATTACKER_LIMIT = 10

MAX_CHART_IPS = 10


# =====================================================
# LOGGING
# =====================================================

LOG_LEVEL = "INFO"

LOG_FILE = (
    BASE_DIR /
    "security_analyzer.log"
)


# =====================================================
# DASHBOARD SETTINGS
# =====================================================

FLASK_HOST = "0.0.0.0"

FLASK_PORT = 5000

DEBUG = True


# =====================================================
# PDF SETTINGS
# =====================================================

PDF_TITLE = (
    "Linux Security Analysis Report"
)

PDF_AUTHOR = (
    "Linux Log Analyzer"
)


# =====================================================
# EXPORT SETTINGS
# =====================================================

EXPORT_CSV = True

EXPORT_JSON = True

EXPORT_PDF = True

EXPORT_CHARTS = True


# =====================================================
# SUPPORTED EVENTS
# =====================================================

EVENT_FAILED_LOGIN = (
    "failed_login"
)

EVENT_SUCCESS_LOGIN = (
    "successful_login"
)

EVENT_ROOT_LOGIN = (
    "root_login"
)

EVENT_SUDO_USAGE = (
    "sudo_activity"
)

EVENT_BRUTE_FORCE = (
    "brute_force"
)


# =====================================================
# COMMON REGEX PATTERNS
# =====================================================

IP_REGEX = (
    r"(?:\d{1,3}\.){3}\d{1,3}"
)

USERNAME_REGEX = (
    r"for\s+([a-zA-Z0-9_\-]+)"
)

FAILED_LOGIN_REGEX = (
    r"Failed password for"
)

SUCCESS_LOGIN_REGEX = (
    r"Accepted password for"
)

SUDO_REGEX = (
    r"sudo"
)

ROOT_REGEX = (
    r"\broot\b"
)