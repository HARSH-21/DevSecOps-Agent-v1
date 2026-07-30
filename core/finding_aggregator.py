"""
finding_aggregator.py

Central finding processing pipeline.

Pipeline:

Raw Findings
      |
Normalizer
      |
Fingerprint
      |
Deduplication
      |
Correlation
      |
Enrichment
      |
Remediation
      |
Risk Scoring
      |
Compliance Mapping
      |
Security Posture
      |
Final Findings
"""

from core.finding_normalizer import FindingNormalizer
from core.finding_deduplicator import FindingDeduplicator
from core.correlator import FindingCorrelator
from core.risk_scorer import RiskScorer

from core.finding_enricher import FindingEnricher
from core.fingerprint import FindingFingerprint
from core.remediation_engine import RemediationEngine

from compliance.compliance_engine import ComplianceEngine


class FindingAggregator:

    def __init__(self):

        self.findings = []

        # Overall repository posture score
        self.security_posture_score = 100

        self.normalizer = FindingNormalizer()

        self.deduplicator = FindingDeduplicator()

        self.correlator = FindingCorrelator()

        self.risk_scorer = RiskScorer()

        self.enricher = FindingEnricher()

        self.fingerprint = FindingFingerprint()

        self.remediation = RemediationEngine()

        self.compliance = ComplianceEngine()

    # =====================================================
    # Main Processing Pipeline
    # =====================================================

    def add_findings(
        self,
        findings
    ):

        print("[+] Preparing Findings")

        print(
            f"[+] Raw Findings Collected : {len(findings)}"
        )

        # ----------------------------------------------

        print("[+] Normalizing Findings")

        findings = self.normalizer.normalize(
            findings
        )

        # ----------------------------------------------

        print("[+] Generating Fingerprints")

        for finding in findings:

            self.fingerprint.add_fingerprint(
                finding
            )

        # ----------------------------------------------

        print("[+] Removing Duplicate Findings")

        findings = self.deduplicator.remove_duplicates(
            findings
        )

        # ----------------------------------------------

        print("[+] Correlating Findings")

        findings = self.correlator.correlate(
            findings
        )

        # ----------------------------------------------

        print("[+] Enriching Findings")

        findings = self.enricher.enrich(
            findings
        )

        # ----------------------------------------------

        print("[+] Adding Remediation Guidance")

        findings = self.remediation.apply(
            findings
        )

        # ----------------------------------------------

        print("[+] Calculating Risk Scores")

        findings = self.risk_scorer.calculate(
            findings
        )

        # ----------------------------------------------

        print("[+] Mapping Compliance Controls")

        findings = self.compliance.analyze(
            findings
        )

        # ----------------------------------------------
        # Repository Security Posture
        # ----------------------------------------------

        self.security_posture_score = (
            self.calculate_security_posture(
                findings
            )
        )

        self.findings = findings

    # =====================================================
    # Security Posture
    # =====================================================

    def calculate_security_posture(
        self,
        findings
    ):
        """
        Calculate an overall repository security posture.

        Starts at 100 and deducts points
        according to finding risk.
        """

        if not findings:
            return 100

        penalties = {

            "CRITICAL": 15,

            "HIGH": 8,

            "MEDIUM": 3,

            "LOW": 1,

            "INFO": 0,

            "UNKNOWN": 0

        }

        score = 100

        for finding in findings:

            score -= penalties.get(
                finding.risk_level,
                0
            )

        return max(score, 0)

    def get_security_posture_score(
        self
    ):

        return self.security_posture_score

    # =====================================================
    # Results
    # =====================================================

    def get_findings(
        self
    ):

        return [

            finding.to_dict()

            for finding in self.findings

        ]

    def summary(
        self
    ):

        severity = {}

        tools = {}

        compliance = {}

        for finding in self.findings:

            severity_value = finding.severity

            severity[severity_value] = (

                severity.get(
                    severity_value,
                    0
                ) + 1

            )

            tools[finding.tool] = (

                tools.get(
                    finding.tool,
                    0
                ) + 1

            )

            metadata = getattr(
                finding,
                "metadata",
                {}
            )

            compliance_data = metadata.get(
                "compliance",
                {}
            )

            for framework, controls in compliance_data.items():

                if framework not in compliance:

                    compliance[framework] = set()

                compliance[framework].update(
                    controls
                )

        for framework in compliance:

            compliance[framework] = list(
                compliance[framework]
            )

        return {

            "total_findings":
                len(self.findings),

            "severity":
                severity,

            "tools":
                tools,

            "compliance":
                compliance,

            "security_posture_score":
                self.security_posture_score

        }