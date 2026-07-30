"""
risk_scorer.py

Enterprise Risk Scoring Engine.

Responsibilities
----------------
- Calculate normalized risk score
- Determine enterprise risk level
- Consider severity
- Consider vulnerability type
- Consider exploitability (CVE presence)
- Populate Finding object fields
- Preserve metadata for reporting
"""


class RiskScorer:

    def __init__(self):

        # Base severity scores
        self.severity_score = {

            "CRITICAL": 95,
            "HIGH": 80,
            "MEDIUM": 50,
            "LOW": 25,
            "INFO": 10,
            "UNKNOWN": 20

        }

        # Keywords representing high-impact vulnerabilities
        self.high_impact_keywords = [

            "sql",
            "injection",
            "command",
            "rce",
            "remote code",
            "ssrf",
            "deserialization",
            "authentication",
            "authorization",
            "idor",
            "xxe",
            "path traversal",
            "template injection",
            "xxe"

        ]

    # -----------------------------------------------------

    def calculate(
        self,
        findings
    ):

        """
        Calculate enterprise risk score
        for every finding.
        """

        for finding in findings:

            severity = str(
                finding.severity or "UNKNOWN"
            ).upper()

            score = self.severity_score.get(
                severity,
                20
            )

            title = str(
                finding.title or ""
            ).lower()

            category = str(
                finding.category or ""
            ).lower()

            # ----------------------------------------
            # High impact vulnerability adjustment
            # ----------------------------------------

            for keyword in self.high_impact_keywords:

                if keyword in title or keyword in category:

                    score += 10
                    break

            # ----------------------------------------
            # CVE bonus
            # ----------------------------------------

            if finding.cve:

                score += 5

            # ----------------------------------------
            # CVSS adjustment
            # ----------------------------------------

            if finding.cvss:

                score = max(
                    score,
                    int(finding.cvss * 10)
                )

            # ----------------------------------------
            # Clamp score
            # ----------------------------------------

            score = min(
                score,
                100
            )

            # ========================================
            # IMPORTANT
            # Populate Finding object
            # ========================================

            finding.risk_score = score

            finding.risk_level = self.get_rating(
                score
            )

            # ========================================
            # Metadata (optional)
            # ========================================

            finding.metadata["risk_score"] = score

            finding.metadata["risk_rating"] = (
                finding.risk_level
            )

            finding.metadata["risk_factors"] = {

                "severity": severity,

                "has_cve": bool(
                    finding.cve
                ),

                "cvss": finding.cvss,

                "high_impact":

                    any(

                        keyword in title
                        or
                        keyword in category

                        for keyword in self.high_impact_keywords

                    )

            }

        return findings

    # -----------------------------------------------------

    def get_rating(
        self,
        score
    ):

        """
        Enterprise risk classification.
        """

        if score >= 90:

            return "CRITICAL"

        elif score >= 75:

            return "HIGH"

        elif score >= 50:

            return "MEDIUM"

        elif score >= 25:

            return "LOW"

        elif score > 0:

            return "INFO"

        return "UNKNOWN"