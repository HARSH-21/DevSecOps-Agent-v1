"""
finding_correlator.py

Correlates findings from multiple security tools.

Responsibilities
----------------
- Merge related findings
- Combine evidence
- Reduce noise
- Increase confidence

Example

Semgrep
    SQL Injection

Trivy
    Vulnerable package

Grype
    Same package CVE

↓

Single correlated finding
"""

from copy import deepcopy

from models.finding import Finding


class FindingCorrelator:

    """
    Correlates related findings.

    Duplicate removal happens earlier.

    Correlation merges
    different findings that
    describe the same risk.
    """

    def correlate(
        self,
        findings: list[Finding]
    ) -> list[Finding]:

        correlated = []

        package_index = {}

        cve_index = {}

        title_location_index = {}

        for finding in findings:

            # ----------------------------------------
            # Package correlation
            # ----------------------------------------

            if finding.package:

                key = (
                    finding.package.lower(),
                    finding.version
                )

                if key in package_index:

                    self._merge(
                        package_index[key],
                        finding
                    )

                    continue

                package_index[key] = finding

                correlated.append(
                    finding
                )

                continue

            # ----------------------------------------
            # CVE correlation
            # ----------------------------------------

            if finding.cve:

                key = finding.cve

                if key in cve_index:

                    self._merge(
                        cve_index[key],
                        finding
                    )

                    continue

                cve_index[key] = finding

                correlated.append(
                    finding
                )

                continue

            # ----------------------------------------
            # Same title + location
            # ----------------------------------------

            key = (
                finding.title,
                finding.location
            )

            if key in title_location_index:

                self._merge(
                    title_location_index[key],
                    finding
                )

                continue

            title_location_index[key] = finding

            correlated.append(
                finding
            )

        return correlated

    # ==================================================

    def _merge(
        self,
        base: Finding,
        new: Finding
    ):

        """
        Merge new finding into base finding.
        """

        base.correlated = True

        # -----------------------------
        # Tool list
        # -----------------------------

        tools = set()

        tools.add(base.tool)

        tools.add(new.tool)

        if "related_tools" in base.metadata:

            tools.update(
                base.metadata["related_tools"]
            )

        base.metadata["related_tools"] = sorted(
            tools
        )

        # -----------------------------
        # References
        # -----------------------------

        refs = set(base.references)

        refs.update(new.references)

        base.references = list(refs)

        # -----------------------------
        # Recommendation
        # -----------------------------

        if (
            not base.recommendation
            and new.recommendation
        ):

            base.recommendation = (
                new.recommendation
            )

        # -----------------------------
        # Description
        # -----------------------------

        if (
            len(new.description)
            >
            len(base.description)
        ):

            base.description = (
                new.description
            )

        # -----------------------------
        # CVSS
        # -----------------------------

        if (
            new.cvss
            and
            (
                base.cvss is None
                or new.cvss > base.cvss
            )
        ):

            base.cvss = new.cvss

        # -----------------------------
        # Severity
        # -----------------------------

        severity_rank = {

            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
            "UNKNOWN": 0

        }

        if severity_rank.get(
            new.severity,
            0
        ) > severity_rank.get(
            base.severity,
            0
        ):

            base.severity = new.severity

        # -----------------------------
        # Metadata
        # -----------------------------

        if new.metadata:

            base.metadata.setdefault(
                "correlated_metadata",
                []
            ).append(
                deepcopy(new.metadata)
            )

    # ==================================================

    def statistics(
        self,
        findings: list[Finding]
    ) -> dict:

        correlated = sum(
            1
            for finding in findings
            if finding.correlated
        )

        return {

            "correlated_findings": correlated,

            "standalone_findings":
                len(findings) - correlated

        }