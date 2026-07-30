"""
orchestrator.py

Controls complete DevSecOps workflow.

Flow:

Planner
   |
Executor
   |
Aggregator
   |
Compliance
   |
Pipeline Security Gate
   |
Reporting
"""


from agent.planner import SecurityPlanner

from agent.executor_manager import SecurityExecutor

from core.finding_aggregator import FindingAggregator

from reporting.report_exporter import ReportExporter

from pipeline.pipeline_engine import PipelineEngine




class SecurityOrchestrator:



    def __init__(self):


        self.planner = SecurityPlanner()


        self.executor = SecurityExecutor()


        self.aggregator = FindingAggregator()


        self.report_exporter = ReportExporter()


        self.pipeline = PipelineEngine()




    def run(
        self,
        target
    ):


        print(
            "[+] Creating security plan"
        )


        plan = self.planner.create_plan(
            target
        )



        print()

        print(
            "[+] Execution Plan:"
        )


        for item in plan:

            print(
                f" - {item}"
            )



        print()

        print(
            "[+] Starting Security Analysis"
        )



        findings = self.executor.execute(

            plan,

            target

        )



        print()

        print(
            "[+] Aggregating Findings"
        )


        self.aggregator.add_findings(
            findings
        )



        normalized_findings = (

            self.aggregator.get_findings()

        )



        summary = (

            self.aggregator.summary()

        )



        # ==========================================
        # Build Result Object
        # ==========================================


        result = {

            "target":

                target,

            "summary":

                summary,

            "findings":

                normalized_findings,

    # Repository Security Posture

    "security_posture_score":

        self.aggregator.get_security_posture_score()

}


        # ==========================================
        # Reporting
        # ==========================================


        print()

        print(
            "[+] Exporting Security Reports"
        )


        reports = self.report_exporter.export_all(

            result

        )


        result["reports"] = reports




        # ==========================================
        # Pipeline Security Gate
        # ==========================================


        print()

        print(
            "[+] Running Security Pipeline Gate"
        )



        pipeline_result = self.pipeline.evaluate(

            normalized_findings

        )



        environment = self.pipeline.environment()



        print(
            f"[+] Pipeline Environment : {environment}"
        )


        print(
            f"[+] Pipeline Status      : {pipeline_result['status']}"
        )



        result["plan"] = plan



        result["pipeline"] = {


            "environment":

                environment,


            "decision":

                pipeline_result

        }



        return result