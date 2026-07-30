"""
sarif_exporter.py

Generates SARIF (Static Analysis Results Interchange Format)
reports for DevSecOps integrations.

Supported Platforms:
- GitHub Advanced Security
- Azure DevOps
- CI/CD security pipelines

Output:
Repository__SARIF_Report__DD-MM-YYYY_HH-MM-SS.sarif
"""


import json
from pathlib import Path

from core.report_utils import generate_report_filename



class SARIFExporter:


    def __init__(
        self,
        output_dir="reports/sarif"
    ):

        self.output_dir = Path(
            output_dir
        )

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )


    # --------------------------------------------------

    def generate(
        self,
        result
    ):

        """
        Generate SARIF report.
        """

        target = result.get(
            "target",
            "repository"
        )


        findings = result.get(
            "findings",
            []
        )


        sarif = {

            "version": "2.1.0",

            "$schema":
                "https://json.schemastore.org/sarif-2.1.0.json",

            "runs": [

                {

                    "tool": {

                        "driver": {

                            "name":
                                "AI DevSecOps Security Agent",

                            "informationUri":
                                "https://github.com",

                            "rules":
                                self._generate_rules(
                                    findings
                                )

                        }

                    },


                    "results":
                        self._generate_results(
                            findings
                        )

                }

            ]

        }



        filename = generate_report_filename(

            target=target,

            report_type="SARIF_Report",

            extension="sarif"

        )


        report_path = (

            self.output_dir

            /

            filename

        )


        with open(

            report_path,

            "w",

            encoding="utf-8"

        ) as file:


            json.dump(

                sarif,

                file,

                indent=4

            )


        return report_path



    # --------------------------------------------------

    def _generate_rules(
        self,
        findings
    ):

        """
        Create SARIF rule definitions.
        """

        rules = []


        seen = set()


        for finding in findings:


            rule_id = finding.get(

                "title",

                "unknown-rule"

            )


            if rule_id in seen:

                continue


            seen.add(
                rule_id
            )


            rules.append(

                {

                    "id":
                        rule_id,


                    "shortDescription":
                        {

                            "text":
                                rule_id

                        }

                }

            )


        return rules



    # --------------------------------------------------

    def _generate_results(
        self,
        findings
    ):

        """
        Convert findings into SARIF results.
        """

        results = []


        for finding in findings:


            results.append(

                {

                    "ruleId":

                        finding.get(

                            "title",

                            "unknown"

                        ),



                    "level":

                        self._map_level(

                            finding.get(

                                "severity",

                                "UNKNOWN"

                            )

                        ),



                    "message":

                        {

                            "text":

                                finding.get(

                                    "description",

                                    finding.get(

                                        "title",

                                        "Security Finding"

                                    )

                                )

                        },



                    "locations":

                        [

                            {

                                "physicalLocation":

                                    {

                                        "artifactLocation":

                                            {

                                                "uri":

                                                    finding.get(

                                                        "location",

                                                        ""

                                                    )

                                            }

                                    }

                            }

                        ]

                }

            )


        return results



    # --------------------------------------------------

    def _map_level(
        self,
        severity
    ):

        """
        SARIF severity mapping.

        SARIF accepts:
        - error
        - warning
        - note
        """

        severity = str(
            severity
        ).upper()



        if severity == "HIGH":

            return "error"



        if severity == "MEDIUM":

            return "warning"



        return "note"