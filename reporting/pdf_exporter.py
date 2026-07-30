"""
pdf_exporter.py

Generates PDF security assessment reports.

Output:
Repository__Technical_Report__DD-MM-YYYY_HH-MM-SS.pdf

Contains:
- Executive summary
- Security posture score
- Severity distribution
- Tool coverage
- Top findings
- Complete vulnerability list
- Remediation guidance
- Compliance mapping (if available)
"""


from pathlib import Path

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib.styles import getSampleStyleSheet

from core.report_utils import generate_report_filename



class PDFExporter:


    def __init__(
        self,
        output_dir="reports/pdf"
    ):

        self.output_dir = Path(
            output_dir
        )

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )


    # -------------------------------------------------

    def generate(
        self,
        result
    ):

        """
        Generate technical security PDF report.
        """


        target = result.get(
            "target",
            "repository"
        )


        findings = result.get(
            "findings",
            []
        )


        filename = generate_report_filename(

            target=target,

            report_type="Technical_Report",

            extension="pdf"

        )


        report_path = (

            self.output_dir

            /

            filename

        )


        document = SimpleDocTemplate(

            str(report_path)

        )


        styles = getSampleStyleSheet()


        content = []


        # ---------------------------------------------
        # Title
        # ---------------------------------------------


        content.append(

            Paragraph(

                "AI DevSecOps Security Assessment Report",

                styles["Title"]

            )

        )


        content.append(
            Spacer(1, 12)
        )


        content.append(

            Paragraph(

                f"Target Repository : {target}",

                styles["Normal"]

            )

        )


        content.append(
            Spacer(1, 12)
        )



        # ---------------------------------------------
        # Summary
        # ---------------------------------------------


        content.append(

            Paragraph(

                "Executive Summary",

                styles["Heading2"]

            )

        )


        score = result.get(

            "security_score",

            "N/A"

        )


        content.append(

            Paragraph(

                f"Security Posture Score : {score}",

                styles["Normal"]

            )

        )


        content.append(

            Paragraph(

                f"Total Findings : {len(findings)}",

                styles["Normal"]

            )

        )


        content.append(
            Spacer(1, 12)
        )



        # ---------------------------------------------
        # Severity Summary
        # ---------------------------------------------


        content.append(

            Paragraph(

                "Severity Distribution",

                styles["Heading2"]

            )

        )


        severity_data = [

            [

                "Severity",

                "Count"

            ]

        ]


        severity = {}


        for finding in findings:


            level = finding.get(

                "severity",

                "UNKNOWN"

            )


            severity[level] = severity.get(

                level,

                0

            ) + 1



        for level, count in severity.items():

            severity_data.append(

                [

                    level,

                    str(count)

                ]

            )



        table = Table(

            severity_data

        )


        table.setStyle(

            TableStyle(

                [

                    ("GRID",(0,0),(-1,-1),0.5,None)

                ]

            )

        )


        content.append(
            table
        )


        content.append(
            Spacer(1,12)
        )



        # ---------------------------------------------
        # Findings
        # ---------------------------------------------


        content.append(

            Paragraph(

                "Security Findings",

                styles["Heading2"]

            )

        )



        for index, finding in enumerate(

            findings,

            start=1

        ):


            title = finding.get(

                "title",

                "Unknown Finding"

            )


            severity = finding.get(

                "severity",

                "UNKNOWN"

            )


            tool = finding.get(

                "tool",

                "Unknown"

            )


            location = finding.get(

                "location",

                ""

            )


            remediation = finding.get(

                "remediation",

                "Review and remediate security issue."

            )



            text = (

                f"{index}. {title}<br/>"

                f"Severity: {severity}<br/>"

                f"Tool: {tool}<br/>"

                f"Location: {location}<br/>"

                f"Remediation: {remediation}"

            )


            content.append(

                Paragraph(

                    text,

                    styles["Normal"]

                )

            )


            content.append(

                Spacer(

                    1,

                    10

                )

            )



        document.build(

            content

        )


        return report_path