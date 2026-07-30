"""
finding_enricher.py

Adds security intelligence to findings.

Responsibilities:
- Add CWE information
- Add OWASP category
- Add CVSS estimation
- Add exploit information placeholder

Future:
- NVD API integration
- OSV API integration
- Threat intelligence enrichment
"""


class FindingEnricher:


    def __init__(self):

        self.owasp_mapping = {

            "sql injection":
                "A03: Injection",

            "command injection":
                "A03: Injection",

            "xss":
                "A03: Injection",

            "cross site scripting":
                "A03: Injection",

            "hardcoded password":
                "A07: Identification and Authentication Failures",

            "secret":
                "A02: Cryptographic Failures",

            "ssrf":
                "A10: Server-Side Request Forgery",

            "xxe":
                "A05: Security Misconfiguration"

        }



    def enrich(
        self,
        findings
    ):


        enriched = []


        for finding in findings:


            title = (
                finding.title
                .lower()
            )


            metadata = finding.metadata



            # -----------------------------
            # OWASP Mapping
            # -----------------------------

            for keyword, category in self.owasp_mapping.items():


                if keyword in title:


                    metadata["owasp_category"] = category

                    break



            # -----------------------------
            # CVSS estimation
            # -----------------------------

            severity = (
                finding.severity
                .upper()
            )


            if severity == "CRITICAL":

                metadata["cvss_score"] = 9.5


            elif severity == "HIGH":

                metadata["cvss_score"] = 8.0


            elif severity == "MEDIUM":

                metadata["cvss_score"] = 5.0


            else:

                metadata["cvss_score"] = 2.0



            # -----------------------------
            # CWE placeholders
            # -----------------------------

            if "sql" in title:


                metadata["cwe"] = "CWE-89"



            elif "xss" in title:


                metadata["cwe"] = "CWE-79"



            elif "secret" in title:


                metadata["cwe"] = "CWE-798"



            else:

                metadata.setdefault(
                    "cwe",
                    "Unknown"
                )



            # Future threat intelligence

            metadata.setdefault(
                "exploit_available",
                False
            )


            enriched.append(
                finding
            )


        return enriched