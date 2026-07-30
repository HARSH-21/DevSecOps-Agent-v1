"""
app.py

AI DevSecOps Agent entry point.

Responsibilities:
- Accept target repository
- Execute security analysis
- Generate readable security reports
"""


from agent.orchestrator import SecurityOrchestrator

from reporting.report_generator import ReportGenerator

from config import REPORT_DIR



def main():

    print("=" * 60)

    print(
        "DevSecOps Security Agent By Harsh Tandel"
    )

    print("=" * 60)


    target = input(
        "Target repository path: "
    )


    print()

    print(
        "[+] Initializing Security Agent"
    )


    orchestrator = SecurityOrchestrator()


    print()

    print(
        "[+] Starting Security Analysis"
    )


    result = orchestrator.run(
        target
    )


    print()

    print(
        "[+] Analysis Completed"
    )


    # =====================================================
    # Report Generation
    # =====================================================

    reporter = ReportGenerator(
        REPORT_DIR
    )


    print()

    print(
        "[+] Generating Security Report"
    )


    # Console Summary

    reporter.generate_console_report(
        result
    )


    # JSON Report

    report_file = reporter.generate_json_report(
        result
    )


    print()

    print("=" * 60)

    print(
        "Report Generation Completed"
    )

    print("=" * 60)


    print()

    print(
        f"JSON Report Saved:"
    )

    print(
        report_file
    )



if __name__ == "__main__":

    main()