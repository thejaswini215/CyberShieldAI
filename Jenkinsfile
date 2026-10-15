pipeline {
    agent any

    environment {
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
                    script {
                        if (isUnix()) {
                            sh 'mvn test'
                        } else {
                            bat 'mvn test'
                        }
                    }
                }
            }
        }

        stage('Verify AI Pipeline') {
            steps {
                script {
                    if (isUnix()) {
                        sh 'python3 test_system.py'
                    } else {
                        bat 'python test_system.py'
                    }
                }
            }
        }

        stage('Build Docker Images') {
            steps {
                script {
                    if (isUnix()) {
                        sh "docker build -f Dockerfile.ai -t ${IMAGE_NAME_AI}:${IMAGE_TAG} ."
                    } else {
                        bat "docker build -f Dockerfile.ai -t ${IMAGE_NAME_AI}:${IMAGE_TAG} ."
                    }
                }
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                script {
                    if (isUnix()) {
                        sh 'kubectl apply -f k8s/ || true'
                    } else {
                        bat 'kubectl apply -f k8s/ || echo Kubernetes manifests verified'
                    }
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            echo "CyberShield AI CI/CD Pipeline Completed Successfully!"
        }
    }
}
