"""
framework_mapper.py

Compliance framework mapping engine.

Responsibilities:
- Map security findings to compliance controls
- Provide framework references
- Support multiple compliance standards

Supported:
- OWASP Top 10
- CWE
- ISO 27001
- SOC 2
- PCI DSS

This is a deterministic mapping layer.
AI reasoning will be added later.
"""


class FrameworkMapper:


    def __init__(self):

        """
        Initialize compliance mappings.
        """

        self.mappings = {

            # ---------------------------------
            # Injection Vulnerabilities
            # ---------------------------------

            "sql injection": {

                "owasp": [
                    "A03:2021 Injection"
                ],

                "cwe": [
                    "CWE-89 SQL Injection"
                ],

                "iso27001": [
                    "A.8.8 Management of Technical Vulnerabilities"
                ],

                "soc2": [
                    "CC7.1 Detection and Monitoring"
                ],

                "pci_dss": [
                    "Requirement 6.2 Secure Software Development"
                ]

            },


            "command injection": {

                "owasp": [
                    "A03:2021 Injection"
                ],

                "cwe": [
                    "CWE-78 OS Command Injection"
                ],

                "iso27001": [
                    "A.8.8 Management of Technical Vulnerabilities"
                ],

                "soc2": [
                    "CC7.1 Detection and Monitoring"
                ],

                "pci_dss": [
                    "Requirement 6.2 Secure Coding"
                ]

            },


            # ---------------------------------
            # Secrets Exposure
            # ---------------------------------

            "secret": {

                "owasp": [
                    "A02:2021 Cryptographic Failures"
                ],

                "cwe": [
                    "CWE-798 Hard-coded Credentials"
                ],

                "iso27001": [
                    "A.5.17 Authentication Information"
                ],

                "soc2": [
                    "CC6.1 Logical Access Controls"
                ],

                "pci_dss": [
                    "Requirement 8 Identification and Authentication"
                ]

            },


            # ---------------------------------
            # Dependency Vulnerabilities
            # ---------------------------------

            "dependency": {

                "owasp": [
                    "A06:2021 Vulnerable and Outdated Components"
                ],

                "cwe": [
                    "CWE-1104 Use of Unmaintained Third Party Components"
                ],

                "iso27001": [
                    "A.8.8 Management of Technical Vulnerabilities"
                ],

                "soc2": [
                    "CC7.1 Vulnerability Detection"
                ],

                "pci_dss": [
                    "Requirement 6.3 Security Vulnerabilities"
                ]

            },


            # ---------------------------------
            # Container Security
            # ---------------------------------

            "container": {

                "owasp": [
                    "A05:2021 Security Misconfiguration"
                ],

                "cwe": [
                    "CWE-16 Configuration"
                ],

                "iso27001": [
                    "A.8.9 Configuration Management"
                ],

                "soc2": [
                    "CC7.2 Security Monitoring"
                ],

                "pci_dss": [
                    "Requirement 2 Secure Configuration"
                ]

            }

        }



    def map_finding(
        self,
        finding
    ):

        """
        Map finding into compliance frameworks.

        Args:
            finding:
                Finding object

        Returns:
            dict
        """


        text = " ".join([

            str(
                getattr(
                    finding,
                    "title",
                    ""
                )
            ),

            str(
                getattr(
                    finding,
                    "description",
                    ""
                )
            ),

            str(
                getattr(
                    finding,
                    "category",
                    ""
                )
            )

        ]).lower()



        result = {

            "owasp": [],

            "cwe": [],

            "iso27001": [],

            "soc2": [],

            "pci_dss": []

        }



        for keyword, mapping in self.mappings.items():


            if keyword in text:


                for framework, values in mapping.items():


                    result[framework].extend(
                        values
                    )



        return self._remove_duplicates(
            result
        )




    def _remove_duplicates(
        self,
        data
    ):

        """
        Remove duplicate compliance references.
        """


        for key in data:

            data[key] = list(
                set(
                    data[key]
                )
            )


        return data