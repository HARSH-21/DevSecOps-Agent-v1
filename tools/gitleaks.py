"""
gitleaks.py

Gitleaks secret scanning adapter.

Responsibilities:
- Check Gitleaks availability
- Build scan command
- Execute secret scanning
- Parse JSON results
- Normalize findings into Finding objects
"""


from pathlib import Path
import json
import shutil


from tools.base_tool import BaseTool
from tools.executor import ToolExecutor
from models.finding import Finding



class GitleaksTool(BaseTool):

    """
    Gitleaks implementation.
    """


    def __init__(self):

        super().__init__(
            name="gitleaks",
            executable="gitleaks"
        )



    def is_available(self) -> bool:
        """
        Check Gitleaks installation.
        """

        return shutil.which(
            self.executable
        ) is not None



    def build_command(
        self,
        target: Path
    ) -> list[str]:
        """
        Build Gitleaks scan command.
        """

        return [

            self.executable,

            "detect",

            "--source",

            str(target),

            "--report-format",

            "json",

            "--report-path",

            "-"

        ]



    def scan(
        self,
        target: Path
    ) -> list[Finding]:
        """
        Execute Gitleaks scan.
        """

        result = ToolExecutor.run(
            self.build_command(target)
        )


        output = result.get(
            "stdout",
            ""
        )


        if not output:

            return []


        return self.parse(
            output
        )



    def parse(
        self,
        output: str
    ) -> list[Finding]:
        """
        Parse Gitleaks JSON output.
        """

        findings = []


        try:

            data = json.loads(
                output
            )


        except json.JSONDecodeError:

            return findings



        if isinstance(data, dict):

            data = [data]



        for secret in data:


            finding = Finding(

                title=secret.get(
                    "RuleID",
                    "Secret Detected"
                ),

                severity="HIGH",

                category="Secrets",

                description=(
                    secret.get(
                        "Description",
                        "Potential secret detected"
                    )
                ),

                tool="gitleaks",

                location=(
                    f"{secret.get('File','')}:"
                    f"{secret.get('StartLine','')}"
                ),

                metadata=secret

            )


            findings.append(
                finding
            )


        return findings