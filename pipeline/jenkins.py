"""
jenkins.py

Jenkins pipeline integration.
"""



class JenkinsPipeline:



    def generate_pipeline(self):

        """
        Generate Jenkinsfile.
        """


        return """

pipeline {


    agent any



    stages {



        stage('Security Scan') {



            steps {



                sh 'python app.py'



            }

        }


    }


}

"""