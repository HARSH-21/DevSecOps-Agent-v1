"""
finding_deduplicator.py

Duplicate vulnerability finding removal.

Responsibilities:
- Remove identical findings
- Keep unique security issues
- Preserve highest quality finding
"""


class FindingDeduplicator:



    def __init__(self):

        self.seen = set()



    def remove_duplicates(
        self,
        findings
    ):

        """
        Remove duplicate findings.

        Duplicate key:
        - title
        - tool
        - location
        - cve
        """


        unique = []

        seen = set()



        for finding in findings:


            key = (

                finding.title,

                finding.tool,

                finding.location,

                finding.cve

            )


            if key in seen:

                continue



            seen.add(
                key
            )


            unique.append(
                finding
            )



        return unique