"""
main.py
Linux Security Log Analyzer & Threat Detection System

Author: Satnam Singh
"""

from pathlib import Path

from analyzer.parser import LogParser
from analyzer.failed_login_detector import FailedLoginDetector
from analyzer.success_login_detector import SuccessLoginDetector
from analyzer.brute_force_detector import BruteForceDetector
from analyzer.threat_scoring import ThreatScorer
from analyzer.suspicious_ip_analyzer import SuspiciousIPAnalyzer

from generators.csv_generator import CSVGenerator
from generators.json_generator import JSONGenerator
from generators.chart_generator import ChartGenerator
from generators.pdf_generator import PDFGenerator

from config.settings import (
    AUTH_LOG_FILE,
    CSV_REPORT_PATH,
    JSON_REPORT_PATH,
    PDF_REPORT_PATH,
)

from utils.logger import get_logger

logger = get_logger()


class SecurityLogAnalyzer:

    def __init__(self):
        self.records = []

    def load_logs(self):

        logger.info("Loading log file...")

        parser = LogParser()

        self.records = parser.parse(AUTH_LOG_FILE)

        logger.info(
            f"Successfully loaded {len(self.records)} records"
        )

    def analyze(self):

        logger.info("Starting analysis...")

        failed_detector = FailedLoginDetector(
            self.records
        )

        success_detector = SuccessLoginDetector(
            self.records
        )

        brute_force_detector = BruteForceDetector(
            self.records
        )

        failed_logins = (
            failed_detector.get_failed_logins()
        )

        successful_logins = (
            success_detector.get_successful_logins()
        )

        brute_force_alerts = (
            brute_force_detector.detect()
        )

        threat_engine = ThreatScorer(
            failed_logins,
            brute_force_alerts
        )

        threat_scores = (
            threat_engine.calculate()
        )

        suspicious_ips = (
            SuspiciousIPAnalyzer(
                threat_scores
            ).rank()
        )

        return {
            "total_records": len(self.records),
            "failed_logins": failed_logins,
            "successful_logins": successful_logins,
            "brute_force_alerts": brute_force_alerts,
            "threat_scores": threat_scores,
            "suspicious_ips": suspicious_ips,
        }

    def generate_reports(self, results):

        logger.info("Generating reports...")

        CSVGenerator().generate(
            results,
            CSV_REPORT_PATH
        )

        JSONGenerator().generate(
            results,
            JSON_REPORT_PATH
        )

        ChartGenerator().generate(
            results
        )

        PDFGenerator().generate(
            results,
            PDF_REPORT_PATH
        )

        logger.info(
            "Reports generated successfully."
        )


def print_summary(results):

    print("\n" + "=" * 60)
    print(" SECURITY ANALYSIS SUMMARY ")
    print("=" * 60)

    print(
        f"Total Log Records       : "
        f"{results['total_records']}"
    )

    print(
        f"Failed Login Attempts   : "
        f"{len(results['failed_logins'])}"
    )

    print(
        f"Successful Logins       : "
        f"{len(results['successful_logins'])}"
    )

    print(
        f"Brute Force Alerts      : "
        f"{len(results['brute_force_alerts'])}"
    )

    print("\nTop Suspicious IPs")

    for item in results["suspicious_ips"][:5]:

        print(
            f"IP: {item['ip']} | "
            f"Score: {item['score']} | "
            f"Severity: {item['severity']}"
        )

    print("=" * 60)


def ensure_directories():

    Path("reports/csv").mkdir(
        parents=True,
        exist_ok=True
    )

    Path("reports/json").mkdir(
        parents=True,
        exist_ok=True
    )

    Path("reports/pdf").mkdir(
        parents=True,
        exist_ok=True
    )

    Path("reports/charts").mkdir(
        parents=True,
        exist_ok=True
    )


def main():

    ensure_directories()

    analyzer = SecurityLogAnalyzer()

    analyzer.load_logs()

    results = analyzer.analyze()

    analyzer.generate_reports(results)

    print_summary(results)

    logger.info(
        "Security analysis completed."
    )


if __name__ == "__main__":
    main()