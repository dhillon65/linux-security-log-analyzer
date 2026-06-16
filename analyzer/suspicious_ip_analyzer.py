"""
analyzer/suspicious_ip_analyzer.py

Suspicious IP Analysis Engine

Consumes threat score results and
produces ranked attacker reports.
"""


class SuspiciousIPAnalyzer:

    def __init__(self, threat_scores):

        self.threat_scores = (
            threat_scores or []
        )

    def rank(self):

        ranked = sorted(

            self.threat_scores,

            key=lambda x:
            x["score"],

            reverse=True

        )

        return ranked

    def get_top_attackers(
        self,
        limit=10
    ):

        return self.rank()[:limit]

    def get_critical_ips(self):

        return [

            item

            for item in self.threat_scores

            if item["severity"]
            == "CRITICAL"

        ]

    def get_high_risk_ips(self):

        return [

            item

            for item in self.threat_scores

            if item["severity"]
            == "HIGH"

        ]

    def get_medium_risk_ips(self):

        return [

            item

            for item in self.threat_scores

            if item["severity"]
            == "MEDIUM"

        ]

    def get_low_risk_ips(self):

        return [

            item

            for item in self.threat_scores

            if item["severity"]
            == "LOW"

        ]

    def get_ip_details(
        self,
        ip_address
    ):

        for item in self.threat_scores:

            if item["ip"] == ip_address:

                return item

        return None

    def get_highest_risk_ip(self):

        ranked = self.rank()

        if ranked:

            return ranked[0]

        return None

    def calculate_statistics(self):

        return {

            "total_ips":
            len(self.threat_scores),

            "critical":
            len(
                self.get_critical_ips()
            ),

            "high":
            len(
                self.get_high_risk_ips()
            ),

            "medium":
            len(
                self.get_medium_risk_ips()
            ),

            "low":
            len(
                self.get_low_risk_ips()
            )
        }

    def generate_dashboard_data(self):

        stats = (
            self.calculate_statistics()
        )

        return {

            "summary": stats,

            "top_attackers":
            self.get_top_attackers(10),

            "highest_risk":
            self.get_highest_risk_ip()

        }

    def generate_report(self):

        report = {

            "statistics":
            self.calculate_statistics(),

            "top_attackers":
            self.get_top_attackers(),

            "critical_ips":
            self.get_critical_ips(),

            "high_risk_ips":
            self.get_high_risk_ips()

        }

        return report

    def print_summary(self):

        stats = (
            self.calculate_statistics()
        )

        print(
            "\nSUSPICIOUS IP ANALYSIS"
        )

        print(
            "-" * 60
        )

        print(
            f"Total Suspicious IPs : "
            f"{stats['total_ips']}"
        )

        print(
            f"Critical             : "
            f"{stats['critical']}"
        )

        print(
            f"High                 : "
            f"{stats['high']}"
        )

        print(
            f"Medium               : "
            f"{stats['medium']}"
        )

        print(
            f"Low                  : "
            f"{stats['low']}"
        )

        print(
            "\nTop Attacker IPs"
        )

        print(
            "-" * 60
        )

        for item in (
            self.get_top_attackers()
        ):

            print(

                f"IP: {item['ip']} | "

                f"Score: {item['score']} | "

                f"Severity: {item['severity']}"

            )