"""
syft.py

Syft SBOM generation adapter.

Responsibilities:
- Check Syft availability
- Generate SBOM from repository
- Store SBOM output
- Return SBOM metadata

Syft does not find vulnerabilities.
It creates software inventory consumed by Grype.
"""

from pathlib import Path
import json
import shutil

from tools.base_tool import BaseTool
from tools.executor import ToolExecutor


class SyftTool(BaseTool):

    """
    Syft SBOM generator.
    """

    def __init__(self):

        super().__init__(
            name="syft",
            executable="syft"
        )


    def is_available(self) -> bool:

        return shutil.which(
            self.executable
        ) is not None



    def build_command(
        self,
        target: Path,
        output_file: Path
    ) -> list[str]:

        return [

            self.executable,

            str(target),

            "-o",

            f"json={output_file}"

        ]



    def generate_sbom(
        self,
        target: Path,
        output_file: Path
    ) -> dict:

        """
        Generate SBOM.

        Returns execution result.
        """


        command = self.build_command(
            target,
            output_file
        )


        result = ToolExecutor.run(
            command,
            timeout=600
        )


        return {

            "success": result["success"],

            "sbom_file": str(output_file),

            "execution_time":
                result["execution_time"],

            "stderr":
                result["stderr"]

        }



    def parse(
        self,
        sbom_file: Path
    ) -> dict:

        """
        Load generated SBOM.
        """

        try:

            with open(
                sbom_file,
                "r",
                encoding="utf-8"
            ) as file:

                return json.load(file)


        except Exception:

            return {}