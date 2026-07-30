"""
technical_report.py

Generates a complete technical security report.

Contains:
- Every finding
- Risk score
- Severity
- Tool
- Location
- CWE/CVE
- Compliance mappings
- Remediation
- References
"""

from collections import Counter


class TechnicalReport:

    """
    Builds a detailed technical report from processed findings.
    """

    def generate(self, result: dict) -> dict:

        findings = result.get("findings", [])

        severity = Counter()
        tools = Counter()

        for finding in findings:

            severity[finding.get("severity", "UNKNOWN")] += 1
            tools[finding.get("tool", "UNKNOWN")] += 1

        report = {

            "title": "Technical Security Report",

            "target": result.get("target"),

            "summary": {

                "total_findings": len(findings),

                "security_posture_score":
                    result.get("security_posture_score", 0),

                "severity_distribution":
                    dict(severity),

                "tool_distribution":
                    dict(tools)

            },

            "findings": []

        }

        for finding in findings:

            report["findings"].append(

                self._build_finding(
                    finding
                )

            )

        return report

    def _build_finding(
        self,
        finding: dict
    ) -> dict:

        return {

            "title":
                finding.get("title"),

            "severity":
                finding.get("severity"),

            "risk_level":
                finding.get("risk_level"),

            "risk_score":
                finding.get("risk_score"),

            "category":
                finding.get("category"),

            "tool":
                finding.get("tool"),

            "location":
                finding.get("location"),

            "line":
                finding.get("line"),

            "description":
                finding.get("description"),

            "cve":
                finding.get("cve"),

            "cwe":
                finding.get("cwe"),

            "owasp":
                finding.get("owasp"),

            "cvss":
                finding.get("cvss"),

            "package":
                finding.get("package"),

            "version":
                finding.get("version"),

            "fixed_version":
                finding.get("fixed_version"),

            "fingerprint":
                finding.get("fingerprint"),

            "references":
                finding.get("references", []),

            "remediation":
                finding.get("remediation"),

            "compliance":
                finding.get("compliance", {}),

            "metadata":
                finding.get("metadata", {})

        }