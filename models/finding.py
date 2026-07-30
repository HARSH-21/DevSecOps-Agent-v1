"""
finding.py

Standard vulnerability data model.

Every security tool finding
will be converted into this format.

Supports:
- Normalization
- Deduplication
- Correlation
- Risk scoring
- AI analysis
"""

from dataclasses import dataclass, field
from typing import Optional



@dataclass
class Finding:


    # ==============================
    # Core Information
    # ==============================

    title: str

    severity: str

    category: str

    description: str

    tool: str



    # ==============================
    # Location / Identity
    # ==============================

    location: Optional[str] = None

    cwe: Optional[str] = None

    cve: Optional[str] = None



    # ==============================
    # Remediation
    # ==============================

    recommendation: Optional[str] = None



    # ==============================
    # Vulnerability Intelligence
    # ==============================

    package: Optional[str] = None

    version: Optional[str] = None

    cvss: Optional[float] = None



    # ==============================
    # Processing Metadata
    # ==============================

    fingerprint: Optional[str] = None

    correlated: bool = False

    duplicate: bool = False



    # ==============================
    # Risk Intelligence
    # ==============================

    risk_score: int = 0

    risk_level: str = "UNKNOWN"



    # ==============================
    # Additional Data
    # ==============================

    references: list = field(
        default_factory=list
    )


    metadata: dict = field(
        default_factory=dict
    )



    def to_dict(
        self
    ):

        return {


            "title":
                self.title,


            "severity":
                self.severity,


            "category":
                self.category,


            "description":
                self.description,


            "tool":
                self.tool,


            "location":
                self.location,


            "cwe":
                self.cwe,


            "cve":
                self.cve,


            "recommendation":
                self.recommendation,


            "package":
                self.package,


            "version":
                self.version,


            "cvss":
                self.cvss,


            "fingerprint":
                self.fingerprint,


            "correlated":
                self.correlated,


            "duplicate":
                self.duplicate,


            "risk_score":
                self.risk_score,


            "risk_level":
                self.risk_level,


            "references":
                self.references,


            "metadata":
                self.metadata

        }