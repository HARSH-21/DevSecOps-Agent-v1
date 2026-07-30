"""
executor_manager.py

Security execution manager.

Responsibilities:
- Map security categories to tools
- Execute security scanners
- Handle tool dependencies
- Collect findings
- Return normalized Finding objects
"""

from pathlib import Path


from tools.semgrep import SemgrepTool
from tools.osv_scanner import OSVScannerTool
from tools.trivy import TrivyTool
from tools.syft import SyftTool
from tools.grype import GrypeTool
from tools.gitleaks import GitleaksTool



class SecurityExecutor:


    def __init__(self):

        """
        Initialize security tool registry.
        """


        self.tools = {


            "semgrep":
                SemgrepTool(),


            "osv":
                OSVScannerTool(),


            "trivy":
                TrivyTool(),


            "syft":
                SyftTool(),


            "grype":
                GrypeTool(),


            "gitleaks":
                GitleaksTool()

        }



        self.execution_map = {


            "sast": [

                "semgrep"

            ],



            "dependency_security": [

                "osv",
                "syft",
                "grype"

            ],



            "container_security": [

                "trivy"

            ],



            "secrets": [

                "gitleaks"

            ]

        }



        # Store generated SBOM path
        self.sbom_file = None



    # =====================================================
    # Main Execution
    # =====================================================

    def execute(
        self,
        plan,
        target
    ):

        """
        Execute complete security analysis.
        """


        all_findings = []


        print()

        print(
            "[+] Security Execution Started"
        )



        target = Path(
            target
        )



        for category in plan:


            print(
                f"[+] Running {category}"
            )


            tools = self.execution_map.get(
                category,
                []
            )


            for tool_name in tools:


                scanner = self.tools.get(
                    tool_name
                )


                if not scanner:


                    print(
                        f"[!] Missing tool: {tool_name}"
                    )

                    continue



                print(
                    f"    -> {tool_name}"
                )



                try:


                    findings = self.run_tool(
                        tool_name,
                        scanner,
                        target
                    )


                    all_findings.extend(
                        self.flatten_findings(
                            findings
                        )
                    )



                except Exception as error:


                    print(
                        f"[!] {tool_name} failed: {error}"
                    )



        return all_findings



    # =====================================================
    # Tool Execution Handler
    # =====================================================

    def run_tool(
        self,
        tool_name,
        scanner,
        target
    ):


        """
        Handle special tool workflows.

        Syft:
            Repository -> SBOM

        Grype:
            SBOM -> Vulnerabilities
        """



        # -------------------------------
        # Syft SBOM generation
        # -------------------------------

        if tool_name == "syft":


            output = (
                Path("outputs")
                /
                "sbom.json"
            )


            output.parent.mkdir(
                exist_ok=True
            )


            result = scanner.generate_sbom(

                target,

                output

            )


            if result.get(
                "success"
            ):


                self.sbom_file = output


                print(
                    f"       SBOM: {output}"
                )


            return []



        # -------------------------------
        # Grype SBOM scanning
        # -------------------------------

        if tool_name == "grype":


            if not self.sbom_file:


                print(
                    "[!] No SBOM available for Grype"
                )


                return []



            return scanner.scan(

                self.sbom_file

            )



        # -------------------------------
        # Normal scanners
        # -------------------------------

        return scanner.scan(
            target
        )



    # =====================================================
    # Result Normalizer
    # =====================================================

    def flatten_findings(
        self,
        findings
    ):

        """
        Convert different tool outputs
        into flat finding list.
        """

        result = []



        if not findings:

            return result



        if isinstance(
            findings,
            list
        ):


            for item in findings:


                if isinstance(
                    item,
                    list
                ):


                    result.extend(
                        self.flatten_findings(
                            item
                        )
                    )


                else:


                    result.append(
                        item
                    )



        else:


            result.append(
                findings
            )



        return result