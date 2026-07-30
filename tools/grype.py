"""
grype.py

Grype vulnerability scanner adapter.

Responsibilities:
- Check Grype availability
- Scan SBOM
- Parse vulnerability results
- Normalize findings

Input:
    Syft SBOM

Output:
    Security findings
"""


from pathlib import Path
import json
import shutil


from tools.base_tool import BaseTool
from tools.executor import ToolExecutor
from models.finding import Finding



class GrypeTool(BaseTool):


    """
    Grype vulnerability scanner.
    """



    def __init__(self):

        super().__init__(
            name="grype",
            executable="grype"
        )



    def is_available(self) -> bool:

        return shutil.which(
            self.executable
        ) is not None



    def build_command(
        self,
        sbom_file: Path
    ) -> list[str]:


        return [

            self.executable,

            f"sbom:{sbom_file}",

            "-o",

            "json"

        ]



    def scan(
        self,
        sbom_file: Path
    ) -> list[Finding]:


        result = ToolExecutor.run(

            self.build_command(
                sbom_file
            ),

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



        matches = data.get(
            "matches",
            []
        )



        for item in matches:


            vulnerability = item.get(
                "vulnerability",
                {}
            )


            artifact = item.get(
                "artifact",
                {}
            )



            finding = Finding(


                title=vulnerability.get(
                    "id",
                    "Unknown CVE"
                ),


                severity=vulnerability.get(
                    "severity",
                    "UNKNOWN"
                ),


                category="SCA",


                description=vulnerability.get(
                    "description",
                    ""
                ),


                tool="grype",


                location=artifact.get(
                    "name",
                    ""
                ),


                cve=vulnerability.get(
                    "id"
                ),


                metadata=item

            )


            findings.append(
                finding
            )


        return findings