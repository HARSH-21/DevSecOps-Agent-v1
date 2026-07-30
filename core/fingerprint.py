"""
fingerprint.py

Finding fingerprint generator.

Creates unique identity for security findings.

Fingerprint is based on:
- vulnerability title
- tool
- location
- CVE/CWE
"""


import hashlib



class FindingFingerprint:



    def generate(
        self,
        finding
    ):

        """
        Generate unique fingerprint.

        Args:
            finding:
                Finding object


        Returns:
            SHA256 fingerprint
        """



        data = [

            finding.title,

            finding.tool,

            finding.location or "",

            finding.cve or "",

            finding.cwe or ""

        ]



        raw_string = "|".join(

            data

        )



        fingerprint = hashlib.sha256(

            raw_string.encode(
                "utf-8"
            )

        ).hexdigest()



        return fingerprint



    def add_fingerprint(
        self,
        finding
    ):

        """
        Attach fingerprint
        into finding metadata.
        """

        fingerprint = self.generate(
            finding
        )


        finding.metadata[
            "fingerprint"
        ] = fingerprint



        return finding