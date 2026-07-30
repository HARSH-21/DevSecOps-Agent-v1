"""
compliance_report.py

Generates a compliance assessment report.

Supported Frameworks

- OWASP Top 10
- OWASP ASVS
- ISO 27001
- NIST SSDF
- CIS Controls
"""

from collections import Counter


class ComplianceReport:

    """
    Builds compliance summary from processed findings.
    """

    FRAMEWORKS = [

        "OWASP Top 10",

        "OWASP ASVS",

        "ISO 27001",

        "NIST SSDF",

        "CIS Controls"

    ]


    def generate(
        self,
        result: dict
    ) -> dict:

        findings = result.get(
            "findings",
            []
        )

        framework_summary = {

            framework: Counter()

            for framework in self.FRAMEWORKS

        }


        for finding in findings:

            compliance = finding.get(
                "compliance",
                {}
            )


            if not compliance:

                continue


            for framework in self.FRAMEWORKS:

                controls = compliance.get(
                    framework,
                    []
                )


                if controls:

                    framework_summary[framework]["mapped"] += 1

                else:

                    framework_summary[framework]["unmapped"] += 1


        report = {

            "title":

                "Compliance Assessment Report",


            "target":

                result.get(
                    "target"
                ),


            "frameworks":

                {}

        }


        for framework in self.FRAMEWORKS:


            mapped = framework_summary[framework]["mapped"]

            unmapped = framework_summary[framework]["unmapped"]


            total = mapped + unmapped


            if total == 0:

                coverage = 0

            else:

                coverage = round(

                    (mapped / total) * 100,

                    2

                )


            report["frameworks"][framework] = {

                "mapped_findings":

                    mapped,


                "unmapped_findings":

                    unmapped,


                "coverage_percent":

                    coverage

            }


        report["recommendations"] = self._recommendations(
            report["frameworks"]
        )


        return report



    def _recommendations(
        self,
        frameworks
    ):

        recommendations = []


        for name, info in frameworks.items():

            coverage = info["coverage_percent"]


            if coverage >= 90:

                recommendations.append(

                    f"{name}: Excellent coverage."

                )

            elif coverage >= 70:

                recommendations.append(

                    f"{name}: Good coverage. Minor improvements recommended."

                )

            elif coverage >= 40:

                recommendations.append(

                    f"{name}: Moderate coverage. Review missing controls."

                )

            else:

                recommendations.append(

                    f"{name}: Low coverage. Compliance review recommended."

                )


        return recommendations