"""
gitlab_ci.py

GitLab CI integration.
"""



class GitLabCI:



    def generate_pipeline(self):

        """
        Generate GitLab CI configuration.
        """


        return """

security_scan:

  stage: security


  script:

    - python app.py


  artifacts:

    paths:

      - reports/

"""