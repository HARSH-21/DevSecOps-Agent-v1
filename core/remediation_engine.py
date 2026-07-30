"""
remediation_engine.py

Security remediation recommendation engine.

Responsibilities:
- Provide remediation guidance
- Map vulnerability types to fixes
- Prepare findings for AI enhancement
"""


class RemediationEngine:



    def __init__(self):


        self.remediation_rules = {


            "sql injection":
            {

                "recommendation":
                    "Use parameterized queries or prepared statements instead of string concatenation.",

                "guidance":
                    "Validate input and use secure database access patterns."

            },



            "command injection":
            {

                "recommendation":
                    "Avoid executing system commands with user-controlled input.",

                "guidance":
                    "Use allowlists and safer APIs instead of shell execution."

            },



            "cross site scripting":
            {

                "recommendation":
                    "Apply output encoding and sanitize untrusted input.",

                "guidance":
                    "Implement context-aware escaping and Content Security Policy."

            },



            "xss":
            {

                "recommendation":
                    "Encode user supplied data before rendering.",

                "guidance":
                    "Use framework security protections."

            },



            "hardcoded password":
            {

                "recommendation":
                    "Remove secrets from source code and use secret management solutions.",

                "guidance":
                    "Rotate exposed credentials immediately."

            },



            "secret":
            {

                "recommendation":
                    "Move sensitive information into environment variables or secret vaults.",

                "guidance":
                    "Prevent committing secrets into repositories."

            },



            "ssrf":
            {

                "recommendation":
                    "Validate and restrict outbound requests.",

                "guidance":
                    "Use allowlists for external destinations."

            }

        }



    def apply(
        self,
        findings
    ):

        """
        Add remediation information
        to findings.
        """


        for finding in findings:


            title = (

                finding.title

                .lower()

            )



            matched = False



            for keyword, data in self.remediation_rules.items():


                if keyword in title:


                    finding.recommendation = (
                        data["recommendation"]
                    )


                    finding.metadata[
                        "remediation_guidance"
                    ] = data["guidance"]


                    matched = True


                    break



            if not matched:


                finding.recommendation = (
                    "Review the vulnerability and apply vendor recommended security fixes."
                )


                finding.metadata[
                    "remediation_guidance"
                ] = (
                    "Perform manual security review."
                )



        return findings