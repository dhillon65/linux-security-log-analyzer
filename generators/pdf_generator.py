from pathlib import Path

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)


class PDFGenerator:

    def generate(
        self,
        results,
        output_file
    ):

        Path(output_file).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        doc = SimpleDocTemplate(
            str(output_file)
        )

        styles = (
            getSampleStyleSheet()
        )

        content = []

        content.append(
            Paragraph(
                "Linux Security Analysis Report",
                styles["Title"]
            )
        )

        content.append(
            Spacer(1, 20)
        )

        content.append(
            Paragraph(
                f"Total Records: "
                f"{results.get('total_records',0)}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Failed Logins: "
                f"{len(results.get('failed_logins',[]))}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Successful Logins: "
                f"{len(results.get('successful_logins',[]))}",
                styles["BodyText"]
            )
        )

        content.append(
            Spacer(1, 20)
        )

        content.append(
            Paragraph(
                "Top Threats",
                styles["Heading2"]
            )
        )

        threats = results.get(
            "threat_scores",
            []
        )[:10]

        for threat in threats:

            content.append(
                Paragraph(
                    f"{threat['ip']} | "
                    f"Score={threat['score']} | "
                    f"{threat['severity']}",
                    styles["BodyText"]
                )
            )

        content.append(
            PageBreak()
        )

        doc.build(content)

        return output_file