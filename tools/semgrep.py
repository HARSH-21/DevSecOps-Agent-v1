"""
semgrep.py

Semgrep security scanner adapter.

Responsibilities:
- Check Semgrep availability
- Build Semgrep scan command
- Execute Semgrep through ToolExecutor
- Parse Semgrep JSON output
- Convert results into standard Finding objects
"""


from pathlib import Path
import json
import shutil


from tools.base_tool import BaseTool
from tools.executor import ToolExecutor
from models.finding import Finding



def map_severity(level: str) -> str:
    """
    Convert Semgrep severity levels
    into standard security severity.
    """

    mapping = {

        "ERROR": "HIGH",

        "WARNING": "MEDIUM",

        "INFO": "LOW"

    }


    return mapping.get(
        level.upper(),
        "INFO"
    )



class SemgrepTool(BaseTool):

    """
    Semgrep implementation of BaseTool.
    """


    def __init__(self):

        super().__init__(
            name="semgrep",
            executable="semgrep"
        )



    def is_available(self) -> bool:
        """
        Check if Semgrep exists.
        """

        return shutil.which(
            self.executable
        ) is not None



    def build_command(
        self,
        target: Path
    ) -> list[str]:
        """
        Build Semgrep CLI command.
        """

        return [

            self.executable,

            "scan",

            "--json",

            str(target)

        ]



    def scan(
        self,
        target: Path
    ) -> list[Finding]:
        """
        Execute Semgrep scan.
        """

        command = self.build_command(
            target
        )


        result = ToolExecutor.run(
            command
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
        """
        Parse Semgrep JSON output.
        """


        findings = []


        try:

            data = json.loads(
                output
            )


        except json.JSONDecodeError:

            return findings



        for result in data.get(
            "results",
            []
        ):


            extra = result.get(
                "extra",
                {}
            )


            finding = Finding(

                title=result.get(
                    "check_id",
                    "Semgrep Finding"
                ),


                severity=map_severity(
                    extra.get(
                        "severity",
                        "INFO"
                    )
                ),


                category="SAST",


                description=extra.get(
                    "message",
                    ""
                ),


                tool="semgrep",


                location=self._get_location(
                    result
                ),


                metadata=result

            )


            findings.append(
                finding
            )


        return findings



    @staticmethod
    def _get_location(
        result: dict
    ) -> str:
        """
        Create readable file location.
        """


        path = result.get(
            "path",
            ""
        )


        line = result.get(
            "start",
            {}
        ).get(
            "line",
            ""
        )


        return f"{path}:{line}"