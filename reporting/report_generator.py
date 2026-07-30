"""
report_generator.py

Responsible for generating and saving security reports.

Outputs
-------
- Console Summary
- Main JSON Report
- Technical Report
- Executive Report
- Compliance Report
"""

from pathlib import Path
import json

from core.report_utils import (
    generate_report_filename,
)

from reporting.report_exporter import (
    ReportExporter,
)


class ReportGenerator:

    def __init__(self, output_dir):

        self.output_dir = Path(output_dir)

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        self.exporter = ReportExporter()

    # --------------------------------------------------

    def generate_console_report(
        self,
        result
    ):

        findings = result.get(
            "findings",
            []
        )

        print()

        print("=" * 70)
        print("DevSecOps Security Assessment Report")
        print("=" * 70)

        print()

        print(
            f"Target : {result.get('target')}"
        )

        print(
            f"Total Findings : {len(findings)}"
        )

        print()

        print("-" * 70)
        print("Security Posture Score")
        print("-" * 70)

        print(
            f"Score : {result.get('security_posture_score',0)}/100"
        )

        print()

        print("-" * 70)
        print("Risk Distribution")
        print("-" * 70)

        risk = {}

        for finding in findings:

            level = finding.get(
                "risk_level",
                "UNKNOWN"
            )

            risk[level] = (
                risk.get(level, 0) + 1
            )

        for level, count in risk.items():

            print(
                f"{level:<12}: {count}"
            )

        print()

        print("-" * 70)
        print("Security Tool Coverage")
        print("-" * 70)

        tools = {}

        for finding in findings:

            tool = finding.get(
                "tool",
                "UNKNOWN"
            )

            tools[tool] = (
                tools.get(tool, 0) + 1
            )

        for tool, count in tools.items():

            print(
                f"{tool:<15}: {count}"
            )

        print()

        print("-" * 70)
        print("Top Risk Findings")
        print("-" * 70)

        ordered = sorted(

            findings,

            key=lambda x:
                x.get(
                    "risk_score",
                    0
                ),

            reverse=True

        )

        for index, finding in enumerate(

            ordered[:10],

            start=1

        ):

            print()

            print(
                f"{index}. {finding.get('title')}"
            )

            print(
                f"Risk     : {finding.get('risk_level')} ({finding.get('risk_score')})"
            )

            print(
                f"Severity : {finding.get('severity')}"
            )

            print(
                f"Tool     : {finding.get('tool')}"
            )

            print(
                f"Location : {finding.get('location')}"
            )

    # --------------------------------------------------

    def generate_json_report(
        self,
        result
    ):

        reports = self.exporter.export(
            result
        )

        reports["scan"] = result

        report_name = generate_report_filename(
            result.get(
                "target",
                "repository"
            ),
            report_type= "AI_DevSecOps_Report",
            extension="json"
        )

        report_path = (
            self.output_dir
            /
            report_name
        )

        with open(
            report_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(

                reports,

                file,

                indent=4

            )

        return report_path
