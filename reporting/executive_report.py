"""
executive_report.py

Generates a high-level executive security report.

Audience:
- Security Managers
- Engineering Managers
- CTO/CISO
- Leadership

Focus:
- Overall security posture
- Business risk
- Compliance overview
- Key recommendations
"""

from collections import Counter


class ExecutiveReport:

    """
    Builds an executive-friendly summary from processed findings.
    """

    def generate(self, result: dict) -> dict:

        findings = result.get("findings", [])

        severity = Counter()
        tools = Counter()

        for finding in findings:

            severity[finding.get("severity", "UNKNOWN")] += 1
            tools[finding.get("tool", "UNKNOWN")] += 1

        posture_score = result.get(
            "security_posture_score",
            0
        )

        return {

            "title": "Executive Security Report",

            "target": result.get(
                "target"
            ),

            "security_posture_score": posture_score,

            "overall_risk": self._overall_risk(
                posture_score
            ),

            "summary": {

                "total_findings": len(findings),

                "severity_distribution": dict(
                    severity
                ),

                "tool_coverage": dict(
                    tools
                )

            },

            "top_findings": self._top_findings(
                findings
            ),

            "business_impact": self._business_impact(
                severity
            ),

            "recommendations": self._recommendations(
                severity
            )

        }

    # ----------------------------------------------------
    # Overall Risk
    # ----------------------------------------------------

    def _overall_risk(
        self,
        score: int
    ) -> str:

        if score >= 90:
            return "LOW"

        if score >= 70:
            return "MEDIUM"

        if score >= 40:
            return "HIGH"

        return "CRITICAL"

    # ----------------------------------------------------
    # Top Findings
    # ----------------------------------------------------

    def _top_findings(
        self,
        findings
    ):

        ordered = sorted(

            findings,

            key=lambda item:
                item.get(
                    "risk_score",
                    0
                ),

            reverse=True

        )

        return ordered[:10]

    # ----------------------------------------------------
    # Business Impact
    # ----------------------------------------------------

    def _business_impact(
        self,
        severity
    ) -> str:

        critical = severity.get(
            "CRITICAL",
            0
        )

        high = severity.get(
            "HIGH",
            0
        )

        if critical > 0:

            return (
                "Critical vulnerabilities require "
                "immediate remediation due to potential "
                "business impact."
            )

        if high > 10:

            return (
                "High-risk vulnerabilities could impact "
                "confidentiality, integrity, or availability."
            )

        if high > 0:

            return (
                "Some high-risk vulnerabilities should be "
                "addressed in the next remediation cycle."
            )

        return (
            "No immediate business-critical security "
            "issues detected."
        )

    # ----------------------------------------------------
    # Recommendations
    # ----------------------------------------------------

    def _recommendations(
        self,
        severity
    ):

        recommendations = []

        if severity.get(
            "CRITICAL",
            0
        ):

            recommendations.append(
                "Immediately remediate all critical findings."
            )

        if severity.get(
            "HIGH",
            0
        ):

            recommendations.append(
                "Prioritize remediation of high-risk vulnerabilities."
            )

        if severity.get(
            "MEDIUM",
            0
        ):

            recommendations.append(
                "Schedule medium-risk issues in the upcoming sprint."
            )

        if severity.get(
            "LOW",
            0
        ):

            recommendations.append(
                "Resolve low-risk findings during routine maintenance."
            )

        if not recommendations:

            recommendations.append(
                "Continue periodic security assessments and monitoring."
            )

        return recommendations