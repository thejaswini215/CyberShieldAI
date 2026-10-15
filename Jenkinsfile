pipeline {
    agent any

    environment {
        DOCKER_REGISTRY = "docker.io/myusername"
        IMAGE_NAME_BACKEND = "cybershield-backend"
        IMAGE_NAME_AI = "cybershield-ai"
        IMAGE_TAG = "${BUILD_NUMBER}"
    }

    stages {
        stage('Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('Build & Test Backend') {
            steps {
                dir('backend') {
                    sh 'mvn clean test'
                }
            }
        }

        stage('Verify AI Pipeline') {
            steps {
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install -r requirements.txt
                    python3 -c "import joblib, sklearn, pandas, fastapi; print('AI Environment Ready')"
                '''
            }
        }

        stage('Build Docker Images') {
            steps {
                sh """
                    docker build -f Dockerfile.ai -t ${DOCKER_REGISTRY}/${IMAGE_NAME_AI}:${IMAGE_TAG} .
                    docker build -f Dockerfile.backend -t ${DOCKER_REGISTRY}/${IMAGE_NAME_BACKEND}:${IMAGE_TAG} .
                """
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                sh """
                    kubectl apply -f k8s/
                    kubectl rollout status deployment/backend-deployment
                    kubectl rollout status deployment/ai-deployment
                """
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            echo "CyberShield AI CI/CD Pipeline Succeeded!"
        }
        failure {
            echo "CyberShield AI CI/CD Pipeline Failed. Check logs."
        }
    }
}
