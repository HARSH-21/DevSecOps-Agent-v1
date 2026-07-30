"""
report_utils.py

Shared reporting utilities.

Responsibilities
----------------
- Generate standardized report filenames
- Extract repository name
- Generate timestamps
- Sanitize filenames

Filename Format
---------------

<Repository>__<ReportType>__<DD-MM-YYYY>_<HH-MM-SS>.<extension>

Examples

WebGoat__AI_DevSecOps_Report__27-07-2026_16-35-12.json

WebGoat__Technical_Report__27-07-2026_16-35-12.pdf

WebGoat__Executive_Report__27-07-2026_16-35-12.pdf

WebGoat__Compliance_Report__27-07-2026_16-35-12.pdf

WebGoat__SARIF_Report__27-07-2026_16-35-12.sarif

WebGoat__HTML_Report__27-07-2026_16-35-12.html
"""

from pathlib import Path
from datetime import datetime
import re


# ---------------------------------------------------------
# Repository Name
# ---------------------------------------------------------

def get_repository_name(
    target
):
    """
    Extract repository name from a filesystem path.
    """

    try:

        repository = Path(
            target
        ).resolve().name

        return sanitize_filename(
            repository
        )

    except Exception:

        return "UnknownRepository"


# ---------------------------------------------------------
# Timestamp
# ---------------------------------------------------------

def get_timestamp():
    """
    Returns timestamp in Indian date format.

    DD-MM-YYYY_HH-MM-SS
    """

    return datetime.now().strftime(
        "%d-%m-%Y_%H-%M-%S"
    )


# ---------------------------------------------------------
# Filename Sanitizer
# ---------------------------------------------------------

def sanitize_filename(
    value
):
    """
    Remove characters invalid in filenames.
    """

    if not value:

        return "Unknown"

    value = str(value)

    value = re.sub(

        r'[<>:"/\\\\|?*]',

        "_",

        value

    )

    value = value.strip()

    return value


# ---------------------------------------------------------
# Report Filename Generator
# ---------------------------------------------------------

def generate_report_filename(
    target,
    report_type="AI_DevSecOps_Report",
    extension="json"
):
    """
    Generate a standardized report filename.

    Example

    WebGoat__Technical_Report__27-07-2026_14-30-22.pdf
    """

    repository = get_repository_name(
        target
    )

    report_type = sanitize_filename(
        report_type
    )

    extension = extension.lower().lstrip(".")

    timestamp = get_timestamp()

    return (

        f"{repository}"

        "__"

        f"{report_type}"

        "__"

        f"{timestamp}"

        "."

        f"{extension}"

    )


# ---------------------------------------------------------
# Future Report Types
# ---------------------------------------------------------

REPORT_TYPES = {

    "main":
        "AI_DevSecOps_Report",

    "technical":
        "Technical_Report",

    "executive":
        "Executive_Report",

    "compliance":
        "Compliance_Report",

    "pdf":
        "PDF_Report",

    "html":
        "HTML_Report",

    "csv":
        "CSV_Report",

    "sarif":
        "SARIF_Report",

    "markdown":
        "Markdown_Report"

}