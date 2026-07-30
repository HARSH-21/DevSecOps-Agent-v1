"""
compliance_engine.py

Compliance analysis engine.

Responsibilities:
- Process security findings
- Map findings to compliance frameworks
- Attach compliance metadata
- Prepare audit-ready evidence structure

Frameworks:
- OWASP Top 10
- CWE
- ISO 27001
- SOC 2
- PCI DSS
"""


from compliance.framework_mapper import FrameworkMapper



class ComplianceEngine:


    def __init__(self):

        """
        Initialize compliance engine.
        """

        self.mapper = FrameworkMapper()



    def analyze(
        self,
        findings
    ):

        """
        Analyze findings against compliance frameworks.

        Args:
            findings:
                List of Finding objects

        Returns:
            Updated findings
        """


        print(
            "[+] Mapping Compliance Controls"
        )


        for finding in findings:


            compliance = self.mapper.map_finding(
                finding
            )


            # Attach compliance metadata

            if hasattr(
                finding,
                "metadata"
            ):


                finding.metadata[

                    "compliance"

                ] = compliance


            else:


                finding.metadata = {

                    "compliance":
                        compliance

                }



        return findings




    def generate_summary(
        self,
        findings
    ):

        """
        Generate compliance coverage summary.

        Returns:
            Framework coverage statistics
        """


        summary = {


            "owasp":

                set(),


            "cwe":

                set(),


            "iso27001":

                set(),


            "soc2":

                set(),


            "pci_dss":

                set()

        }



        for finding in findings:


            compliance = (

                finding.metadata
                .get(
                    "compliance",
                    {}
                )

            )


            for framework in summary:


                values = compliance.get(
                    framework,
                    []
                )


                summary[framework].update(
                    values
                )



        # Convert sets to lists
        # for JSON reporting


        for framework in summary:


            summary[framework] = list(
                summary[framework]
            )



        return summary