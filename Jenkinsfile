pipeline {
    agent any

    environment {
        IMAGE_NAME = 'hbillsoft-mobile'
        EC2_USER   = 'ubuntu'
        EC2_HOST   = credentials('EC2_HOST')        // store your EC2 public IP in Jenkins credentials
        SSH_KEY    = credentials('EC2_SSH_KEY')     // store your .pem key in Jenkins credentials
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t $IMAGE_NAME:latest .'
            }
        }

        stage('Deploy to EC2') {
            steps {
                sh '''
                    # Copy updated files to EC2
                    scp -i $SSH_KEY -o StrictHostKeyChecking=no \
                        docker-compose.yml Dockerfile requirements.txt \
                        mobile_server.py mobile_order.html \
                        $EC2_USER@$EC2_HOST:/home/$EC2_USER/hbillsoft/

                    # SSH into EC2 and redeploy
                    ssh -i $SSH_KEY -o StrictHostKeyChecking=no $EC2_USER@$EC2_HOST << 'ENDSSH'
                        cd /home/ubuntu/hbillsoft
                        docker compose down
                        docker compose up --build -d
                        docker image prune -f
ENDSSH
                '''
            }
        }
    }

    post {
        success {
            echo 'Deployment successful!'
        }
        failure {
            echo 'Deployment failed. Check logs above.'
        }
    }
}
