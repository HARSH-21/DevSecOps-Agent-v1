"""
report_exporter.py

Central reporting export controller.

Responsible for:
- Calling different report exporters
- Managing multi-format report generation

Supported formats:
- JSON
- PDF
- SARIF
- HTML
- CSV
"""


from pathlib import Path


from reporting.pdf_exporter import PDFExporter
from reporting.sarif_exporter import SARIFExporter
from reporting.html_exporter import HTMLExporter
from reporting.csv_exporter import CSVExporter



class ReportExporter:


    def __init__(
        self,
        output_dir="reports"
    ):

        self.output_dir = Path(
            output_dir
        )


        self.pdf_exporter = PDFExporter(
            output_dir
        )


        self.sarif_exporter = SARIFExporter(
            output_dir
        )


        self.html_exporter = HTMLExporter(
            output_dir
        )


        self.csv_exporter = CSVExporter(
            output_dir
        )



    # -------------------------------------------------

    def export_all(
        self,
        result
    ):

        """
        Generate all report formats.
        """


        reports = {}



        print(
            "[+] Generating PDF Report"
        )


        reports["pdf"] = str(

            self.pdf_exporter.generate(

                result

            )

        )



        print(
            "[+] Generating SARIF Report"
        )


        reports["sarif"] = str(

            self.sarif_exporter.generate(

                result

            )

        )



        print(
            "[+] Generating HTML Report"
        )


        reports["html"] = str(

            self.html_exporter.generate(

                result

            )

        )



        print(
            "[+] Generating CSV Report"
        )


        reports["csv"] = str(

            self.csv_exporter.generate(

                result

            )

        )



        return reports



    # -------------------------------------------------

    def export(self, result):
        """
        Backward compatibility wrapper.

        Called by report_generator.py
        """

        return self.export_all(result)

    # -------------------------------------------------

    def export_selected(
        self,
        result,
        formats
    ):

        """
        Generate selected report formats.

        Example:

        formats=[
            "pdf",
            "sarif"
        ]
        """


        available = {


            "pdf":

                self.pdf_exporter.generate,


            "sarif":

                self.sarif_exporter.generate,


            "html":

                self.html_exporter.generate,


            "csv":

                self.csv_exporter.generate

        }



        reports = {}



        for report_type in formats:


            exporter = available.get(

                report_type

            )


            if exporter:


                reports[report_type] = str(

                    exporter(

                        result

                    )

                )


        return reports