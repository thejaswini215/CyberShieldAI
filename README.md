# CyberShield AI — Phishing URL Detection & Threat Analysis

CyberShield AI is an intelligent end-to-end cybersecurity solution that detects whether a website URL is likely legitimate or potentially phishing using a machine-learning model trained on the UCI PhiUSIIL Phishing URL Dataset (235,795 URLs). The system features an AI agent that extracts suspicious structural indicators, provides contextual risk assessments, and recommends defensive actions.

---

## 🏗️ Architecture Overview

```
                      +-----------------------------+
                      |   React Web Frontend        |
                      |   (URL Input, Threat Score, |
                      |    AI Insights, History)    |
                      +--------------+--------------+
                                     |
                                     v HTTP REST
                      +--------------+--------------+
                      |   Spring Boot Backend (8080)|
                      |   (Validation, Scan History,|
                      |    JPA Entity & DB Audit)   |
                      +-------+--------------+------+
                              |              |
                    HTTP REST |              | JPA / JDBC
                              v              v
        +---------------------+----+    +----+------------------+
        |   Python FastAPI (8000)  |    |   MySQL / H2 Database |
        |   - Scikit-Learn TF-IDF  |    |   - Scan Records      |
        |   - Logistic Regression  |    |   - Audit History     |
        |   - AI Threat Reasoning  |    +-----------------------+
        +--------------------------+
```

---

## 📂 Project Structure

```
CyberShieldAI/
├── data/
│   └── PhiUSIIL_Phishing_URL_Dataset.csv   # 56.8 MB public dataset (UCI)
├── models/
│   └── phishing_model.joblib               # Serialized TF-IDF + Classifier pipeline
├── backend/                                # Java 21 + Spring Boot 3.2 backend
│   ├── src/main/java/com/cybershield/
│   │   ├── CyberShieldApplication.java
│   │   ├── controller/ScanController.java
│   │   ├── dto/
│   │   ├── model/ScanRecord.java
│   │   ├── repository/ScanRepository.java
│   │   └── service/ScanService.java
│   ├── src/main/resources/
│   │   ├── application.yml
│   │   └── static/index.html               # Embedded React dashboard
│   └── pom.xml
├── frontend/                               # Modern React.js dashboard
│   └── index.html
├── k8s/                                    # Kubernetes Deployment & Service manifests
│   ├── deployment.yaml
│   └── services.yaml
├── app.py                                  # FastAPI ML Inference & AI Agent Service
├── train_model.py                          # ML Training pipeline
├── requirements.txt                        # Python dependencies
├── Dockerfile.ai                           # Docker image for Python AI service
├── Dockerfile.backend                      # Docker image for Spring Boot
├── Dockerfile.frontend                     # Docker image for React/Nginx
├── docker-compose.yml                      # Multi-container orchestration
└── Jenkinsfile                             # Automated CI/CD pipeline
```

---

## 🚀 Quickstart Guide

### 1. Train the Machine Learning Model

The dataset is already downloaded into `data/PhiUSIIL_Phishing_URL_Dataset.csv`.

To train the character n-gram TF-IDF Logistic Regression pipeline:
```bash
# Activate virtual environment
.\venv\Scripts\activate   # Windows
# or: source venv/bin/activate  # macOS / Linux

python train_model.py
```
This will train on the dataset, output accuracy, classification report, and confusion matrix, then save the artifact to `models/phishing_model.joblib`.

### 2. Run the Python AI Prediction Service

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```
Endpoints:
- `GET /health` : Health check & model status
- `POST /predict` : Raw ML inference (`{"url": "https://..."}`)
- `POST /agent/analyze` : Full AI agent inspection with heuristic breakdown and recommendations

### 3. Run the Java Spring Boot Backend

```bash
cd backend
mvn spring-boot:run
```
- By default, uses an embedded **H2 database** with zero extra setup needed.
- To use **MySQL**, activate the `mysql` profile:
  ```bash
  mvn spring-boot:run -Dspring-boot.run.profiles=mysql
  ```
- Endpoints:
  - `POST /api/scan` : Dispatches URL to AI agent, persists audit record
  - `GET /api/history` : Retrieves recent scan history
  - `GET /api/stats` : Returns threat breakdown metrics
  - `GET /api/health` : Backend health probe

### 4. Access the React Web UI

- Open `frontend/index.html` in any web browser, or:
- Navigate to `http://localhost:8080` once Spring Boot is running (served from Spring Boot static resources).

---

## 🐳 Docker & DevOps Deployment

### Using Docker Compose:
```bash
docker-compose up --build
```
This spins up:
- **MySQL 8.0** on `localhost:3306`
- **Python AI Microservice** on `localhost:8000`
- **Spring Boot Backend** on `localhost:8080`
- **React Frontend** on `localhost:3000`

### Kubernetes Deployment:
```bash
kubectl apply -f k8s/
```
Deployments include auto-scaling, resource limits, and health checks across microservices.
