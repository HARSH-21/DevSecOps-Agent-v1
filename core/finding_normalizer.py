"""
finding_normalizer.py

Normalizes findings from different
security tools into a common format.
"""


from models.finding import Finding



class FindingNormalizer:



    def normalize(
        self,
        findings
    ):

        """
        Normalize list of findings.
        """

        normalized = []


        for item in self.flatten(findings):


            if not isinstance(
                item,
                Finding
            ):

                continue



            self._normalize_title(
                item
            )


            self._normalize_severity(
                item
            )


            self._normalize_category(
                item
            )


            normalized.append(
                item
            )



        return normalized



    # =====================================
    # Flatten protection
    # =====================================

    def flatten(
        self,
        findings
    ):

        result = []


        if not findings:

            return result



        for item in findings:


            if isinstance(
                item,
                list
            ):

                result.extend(
                    self.flatten(
                        item
                    )
                )


            else:

                result.append(
                    item
                )


        return result



    # =====================================
    # Normalization Rules
    # =====================================

    def _normalize_title(
        self,
        finding
    ):


        if not finding.title:

            finding.title = (
                "Unknown Security Finding"
            )



        finding.title = (
            str(
                finding.title
            ).strip()
        )



    def _normalize_severity(
        self,
        finding
    ):


        if not finding.severity:

            finding.severity = "UNKNOWN"



        finding.severity = (
            str(
                finding.severity
            ).upper()
        )



    def _normalize_category(
        self,
        finding
    ):


        if not finding.category:

            finding.category = "GENERAL"