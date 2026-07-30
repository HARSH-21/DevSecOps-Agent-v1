"""
html_exporter.py

Generates HTML security assessment reports.

Output:

Repository__HTML_Report__DD-MM-YYYY_HH-MM-SS.html

Purpose:
- Browser readable security report
- Easy sharing
- Future dashboard integration
"""


from pathlib import Path
import html

from core.report_utils import generate_report_filename



class HTMLExporter:


    def __init__(
        self,
        output_dir="reports/html"
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
        Generate HTML security report.
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

            report_type="HTML_Report",

            extension="html"

        )


        report_path = (

            self.output_dir

            /

            filename

        )


        html_content = self._build_html(

            result,

            findings

        )


        with open(

            report_path,

            "w",

            encoding="utf-8"

        ) as file:

            file.write(

                html_content

            )


        return report_path



    # -------------------------------------------------

    def _build_html(
        self,
        result,
        findings
    ):

        """
        Build complete HTML document.
        """


        target = html.escape(

            str(

                result.get(

                    "target",

                    "repository"

                )

            )

        )


        score = result.get(

            "security_score",

            "N/A"

        )


        rows = ""


        for index, finding in enumerate(

            findings,

            start=1

        ):


            title = html.escape(

                str(

                    finding.get(

                        "title",

                        "Unknown"

                    )

                )

            )


            severity = html.escape(

                str(

                    finding.get(

                        "severity",

                        "UNKNOWN"

                    )

                )

            )


            tool = html.escape(

                str(

                    finding.get(

                        "tool",

                        "Unknown"

                    )

                )

            )


            location = html.escape(

                str(

                    finding.get(

                        "location",

                        ""

                    )

                )

            )


            remediation = html.escape(

                str(

                    finding.get(

                        "remediation",

                        "Review and fix security issue."

                    )

                )

            )


            rows += f"""

            <tr>

                <td>{index}</td>

                <td>{title}</td>

                <td>{severity}</td>

                <td>{tool}</td>

                <td>{location}</td>

                <td>{remediation}</td>

            </tr>

            """



        return f"""

<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">


<title>
AI DevSecOps Security Report
</title>


<style>

body {{

    font-family: Arial, sans-serif;

    margin: 40px;

    background-color: #f8f9fa;

}}


h1 {{

    color: #222;

}}


.summary {{

    background: white;

    padding: 20px;

    border-radius: 8px;

    margin-bottom: 20px;

}}


table {{

    width:100%;

    border-collapse:collapse;

    background:white;

}}


th {{

    background:#333;

    color:white;

    padding:10px;

}}


td {{

    border:1px solid #ddd;

    padding:8px;

    font-size:14px;

}}


tr:nth-child(even) {{

    background:#f2f2f2;

}}


</style>


</head>


<body>


<h1>
AI DevSecOps Security Assessment Report
</h1>


<div class="summary">


<h2>
Repository Details
</h2>


<p>
<b>Target:</b> {target}
</p>


<p>
<b>Total Findings:</b> {len(findings)}
</p>


<p>
<b>Security Posture Score:</b> {score}
</p>


</div>



<h2>
Security Findings
</h2>



<table>


<tr>

<th>ID</th>

<th>Finding</th>

<th>Severity</th>

<th>Tool</th>

<th>Location</th>

<th>Remediation</th>

</tr>


{rows}


</table>


</body>


</html>

"""