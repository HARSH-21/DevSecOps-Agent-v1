"""
osv_scanner.py

OSV Scanner integration.

Responsibilities
----------------
- Detect dependency lock files
- Execute OSV-Scanner
- Parse JSON results
- Normalize findings
"""

from __future__ import annotations

import json
from pathlib import Path

from config import TOOLS
from models.finding import Finding
from tools.base_tool import BaseTool
from tools.executor import ToolExecutor


class OSVScannerTool(BaseTool):

    def __init__(self):

        super().__init__(
            "osv-scanner",
            TOOLS.get("osv") or "osv-scanner"
        )

    def is_available(self):

        return TOOLS.get("osv") is not None

    def build_command(self, lockfile: Path):

        return [
            self.executable,
            "scan",
            "--lockfile",
            str(lockfile),
            "--format",
            "json"
        ]

    def parse(self, output: str):

        try:
            return json.loads(output)

        except Exception:
            return {}

    def normalize(self, data):

        findings = []

        results = data.get("results", [])

        for result in results:

            package = result.get("package", {})

            package_name = package.get("name", "Unknown")

            for vuln in result.get("vulnerabilities", []):

                findings.append(
                    Finding(
                        title=vuln.get("id", "Unknown"),
                        severity="HIGH",
                        category="SCA",
                        description=vuln.get(
                            "summary",
                            ""
                        ),
                        tool=self.name,
                        location=package_name,
                        cve=vuln.get("id"),
                        recommendation=None,
                        metadata=vuln
                    ).to_dict()
                )

        return findings

    def scan(
        self,
        target
    ):

        target = Path(target)

        lock_files = [

            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",

            "poetry.lock",
            "Pipfile.lock",
            "requirements.txt",

            "go.sum",

            "Cargo.lock",

            "composer.lock",

            "Gemfile.lock"

        ]

        detected = None

        for filename in lock_files:

            candidate = target / filename

            if candidate.exists():

                detected = candidate

                break

        if detected is None:

            return [

                Finding(
                    title="Dependency lock file missing",
                    severity="INFO",
                    category="SCA",
                    description=(
                        "No supported dependency lock file "
                        "was detected. Falling back to "
                        "Syft + Grype analysis."
                    ),
                    tool=self.name,
                    location=str(target)
                ).to_dict()

            ]

        result = ToolExecutor.run(

            self.build_command(detected),

            cwd=target,

            timeout=600

        )

        if not result["success"]:

            return [

                Finding(
                    title="OSV Scan Failed",
                    severity="LOW",
                    category="SCA",
                    description=result["stderr"],
                    tool=self.name,
                    location=str(detected)
                ).to_dict()

            ]

        parsed = self.parse(

            result["stdout"]

        )

        return self.normalize(

            parsed

        )