"""
trivy.py

Trivy security scanner adapter.

Responsibilities:
- Check Trivy availability
- Scan filesystem
- Parse vulnerability results
- Normalize findings
"""

from pathlib import Path
import json
import shutil


from tools.base_tool import BaseTool
from tools.executor import ToolExecutor
from models.finding import Finding



class TrivyTool(BaseTool):

    """
    Trivy implementation.
    """


    def __init__(self):

        super().__init__(
            name="trivy",
            executable="trivy"
        )



    def is_available(self) -> bool:

        return shutil.which(
            self.executable
        ) is not None



    def build_command(
        self,
        target: Path
    ) -> list[str]:

        return [

            self.executable,

            "fs",

            "--format",

            "json",

            str(target)

        ]



    def scan(
        self,
        target: Path
    ) -> list[Finding]:

        result = ToolExecutor.run(
            self.build_command(target),
            timeout=600
        )


        if not result["stdout"]:

            return []


        return self.parse(
            result["stdout"]
        )



    def parse(
        self,
        output: str
    ) -> list[Finding]:

        findings = []


        try:

            data = json.loads(
                output
            )


        except json.JSONDecodeError:

            return findings



        for result in data.get(
            "Results",
            []
        ):


            vulnerabilities = result.get(
                "Vulnerabilities",
                []
            )


            for vuln in vulnerabilities:


                finding = Finding(

                    title=vuln.get(
                        "VulnerabilityID",
                        "Trivy Finding"
                    ),

                    severity=vuln.get(
                        "Severity",
                        "UNKNOWN"
                    ),

                    category="Container/IaC",

                    description=vuln.get(
                        "Title",
                        ""
                    ),

                    tool="trivy",

                    location=result.get(
                        "Target",
                        ""
                    ),

                    metadata=vuln

                )


                findings.append(
                    finding
                )


        return findings