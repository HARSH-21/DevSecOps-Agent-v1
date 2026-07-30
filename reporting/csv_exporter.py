"""
csv_exporter.py

Generates CSV vulnerability reports.

Output:

Repository__Findings_Report__DD-MM-YYYY_HH-MM-SS.csv

Purpose:
- Import into Excel
- Vulnerability tracking
- Risk management workflows
- Ticket creation pipelines
"""


from pathlib import Path
import csv

from core.report_utils import generate_report_filename



class CSVExporter:


    def __init__(
        self,
        output_dir="reports/csv"
    ):

        self.output_dir = Path(
            output_dir
        )

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )



    # -------------------------------------------------

    def generate(
        self,
        result
    ):

        """
        Generate CSV vulnerability report.
        """


        target = result.get(
            "target",
            "repository"
        )


        findings = result.get(
            "findings",
            []
        )


        filename = generate_report_filename(

            target=target,

            report_type="Findings_Report",

            extension="csv"

        )


        report_path = (

            self.output_dir

            /

            filename

        )


        headers = [

            "ID",

            "Title",

            "Severity",

            "Risk Score",

            "Tool",

            "Location",

            "Description",

            "CWE",

            "OWASP",

            "Compliance",

            "Remediation"

        ]



        with open(

            report_path,

            "w",

            newline="",

            encoding="utf-8"

        ) as file:


            writer = csv.DictWriter(

                file,

                fieldnames=headers

            )


            writer.writeheader()



            for index, finding in enumerate(

                findings,

                start=1

            ):


                writer.writerow(

                    {

                        "ID":

                            index,


                        "Title":

                            finding.get(

                                "title",

                                ""

                            ),



                        "Severity":

                            finding.get(

                                "severity",

                                ""

                            ),



                        "Risk Score":

                            finding.get(

                                "risk_score",

                                ""

                            ),



                        "Tool":

                            finding.get(

                                "tool",

                                ""

                            ),



                        "Location":

                            finding.get(

                                "location",

                                ""

                            ),



                        "Description":

                            finding.get(

                                "description",

                                ""

                            ),



                        "CWE":

                            self._extract_value(

                                finding,

                                "cwe"

                            ),



                        "OWASP":

                            self._extract_value(

                                finding,

                                "owasp"

                            ),



                        "Compliance":

                            self._extract_value(

                                finding,

                                "compliance"

                            ),



                        "Remediation":

                            finding.get(

                                "remediation",

                                ""

                            )

                    }

                )


        return report_path



    # -------------------------------------------------

    def _extract_value(
        self,
        finding,
        key
    ):

        """
        Safely extract optional fields.
        """


        value = finding.get(

            key,

            ""

        )


        if isinstance(

            value,

            list

        ):

            return ", ".join(

                map(

                    str,

                    value

                )

            )


        return value