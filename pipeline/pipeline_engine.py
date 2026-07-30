"""
pipeline_engine.py

DevSecOps pipeline controller.

Responsibilities:
- Detect CI platform
- Apply security gates
- Decide pipeline status
"""


from pipeline.ci_detector import CIDetector



class PipelineEngine:



    def __init__(self):


        self.detector = CIDetector()



    def evaluate(
        self,
        findings
    ):

        """
        Evaluate security findings.

        Rules:

        Critical / Very High risk
            -> Fail pipeline

        Otherwise
            -> Pass
        """


        print(
            "[+] Evaluating Security Gate"
        )


        for finding in findings:


            risk = finding.get(
                "risk_score",
                0
            )


            severity = finding.get(
                "severity",
                ""
            ).upper()



            if (

                severity in [
                    "CRITICAL"
                ]

                or

                risk >= 90

            ):


                return {


                    "status":
                        "FAILED",


                    "reason":
                        "Critical security issue detected"

                }




        return {


            "status":
                "PASSED",


            "reason":
                "No blocking security issues"

        }




    def environment(self):


        return self.detector.detect()