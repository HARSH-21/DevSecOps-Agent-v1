"""
ci_detector.py

Detect CI/CD execution environment.

Supported:
- GitHub Actions
- GitLab CI
- Jenkins
- Local
"""

import os



class CIDetector:



    def detect(self):

        """
        Detect active CI platform.
        """


        if os.getenv(
            "GITHUB_ACTIONS"
        ):

            return "github_actions"



        if os.getenv(
            "GITLAB_CI"
        ):

            return "gitlab_ci"



        if os.getenv(
            "JENKINS_URL"
        ):

            return "jenkins"



        return "local"