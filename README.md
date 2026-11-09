# CloudGuard — Secrets Leakage Detection and Security Analysis Platform

[![Tests](https://img.shields.io/badge/tests-31%20passed-success.svg)](#running-tests)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](#technology-stack)
[![React](https://img.shields.io/badge/frontend-React%20%2B%20Vite-61dafb.svg)](#technology-stack)
[![ML](https://img.shields.io/badge/ML-Random%20Forest%20Classifier-orange.svg)](#machine-learning-component)

CloudGuard is a cloud-based secrets leakage detection application that scans uploaded source-code archives for accidentally exposed credentials. It combines modular **rule-based pattern matching** with a trained **Random Forest machine learning classifier** (`scikit-learn`), calculates a transparent **security score**, and presents masked evidence with actionable remediation guidance in a clean, restrained dashboard.

---

## Architecture Overview

```text
                         Developer
                             |
                             v
                    React Web Application
               (Vite / Responsive Clean UI)
                             |
                         HTTPS / REST
                             |
                             v
                       Flask Backend
                   /          |          \
                  /           |           \
           Authentication  Scan Service  Database
           (JWT/Cookies)                 (SQLite / MySQL)
                             |
                      Upload Validation
                     (Size / Bomb Defense)
                             |
                      Private AWS S3
                    (SSE-S3 Encryption)
                             |
                     Safe ZIP Inspection
                   (No Code Execution)
                             |
                   Candidate Extraction Layer
                             |
               +-------------+-------------+
               |                           |
               v                           v
        Rule-Based Engine             ML Classifier
     (regex/context/entropy)        (Random Forest)
               |                           |
               +-------------+-------------+
                             |
                    Result Correlation
                             |
                     Risk Assessment
                             |
                  Security Score + Findings
                             |
                   Masked Database Records
                             |
                             v
                    React Scan Report
```

---

## Key Features

1. **Safe Archive Inspection:** Uploaded ZIP archives are decompressed in an isolated sandbox with strict uncompressed byte limits and entry counts to prevent path traversal (`../../`) and decompression bombs. **Uploaded code is never executed, imported, or installed.**
2. **Hybrid Detection Engine:**
   - **Rule Engine:** Modular regex rules for AWS Access Keys & Secrets, GitHub Tokens, Database Connection URIs with embedded passwords, Private Key blocks, API Tokens, and generic passwords.
   - **Random Forest ML Classifier:** Genuinely trained `RandomForestClassifier` evaluating 14 engineered features (Shannon entropy, character ratios, known prefixes, context keyword weights, and quoting).
3. **Transparent Security Score:**
   $$\text{Security Score} = \max(0, 100 - \sum \text{severity deductions})$$
   - Critical: **-30** points
   - High: **-15** points
   - Medium: **-7** points
   - Low: **-2** points
4. **Zero Secret Exposure:** Raw secrets are **never** persisted to the database, logged to CloudWatch, or sent in API responses. All candidates are immediately masked (e.g., `AKIA****WXYZ` or `********`).
5. **AWS Cloud-Native:** Private S3 storage with server-side encryption (SSE-S3), IAM instance profiles for EC2, Nginx reverse proxy, and CloudWatch logs integration.

---

## Technology Stack

| Layer | Technology | Responsibility |
|---|---|---|
| **Frontend** | React 19 + Vite | Minimal, responsive developer dashboard |
| **Styling** | Clean CSS Design System | High-contrast, accessible, restrained theme |
| **Backend** | Python + Flask | Authentication, scan pipeline, REST APIs |
| **ORM / DB** | Flask-SQLAlchemy / SQLAlchemy | Users, scans, findings (SQLite / MySQL) |
| **ML Engine** | scikit-learn (`RandomForestClassifier`) | Binary classification of candidate tokens |
| **Model Persistence** | joblib | Serialized model and metadata |
| **Cloud Storage** | AWS S3 (`boto3`) | Private encrypted archive storage |
| **Deployment** | AWS EC2 + Nginx + Gunicorn | Production web hosting and reverse proxy |
| **Access Control** | AWS IAM Role | Least-privilege S3 bucket access |

---

## Project Structure

```text
cloudguard/
├── backend/
│   ├── app/
│   │   ├── __init__.py           # Flask app factory & static routing
│   │   ├── config.py             # Environment configuration
│   │   ├── extensions.py         # SQLAlchemy instance
│   │   ├── models/               # User, Scan, Finding models
│   │   ├── routes/               # auth.py, scans.py, dashboard.py, health.py
│   │   ├── services/             # scan_service, archive_service, storage_service, risk_service
│   │   ├── scanner/              # rules.py, entropy.py, candidate_extractor.py, result_combiner.py
│   │   └── utils/                # auth.py, masking.py
│   ├── tests/                    # 30 automated unit & integration tests
│   ├── requirements.txt
│   └── run.py
├── ml/
│   ├── dataset/                  # Synthetic training CSV
│   ├── models/                   # Serialized secret_classifier.joblib
│   ├── evaluation/               # Actual metrics.json report
│   ├── features.py               # 14 engineered candidate features
│   ├── generate_dataset.py       # Reproducible synthetic dataset generator
│   ├── train_model.py            # Random Forest training and evaluation script
│   ├── predictor.py              # ML inference adapter
│   └── README.md
├── frontend/
│   ├── src/
│   │   ├── api/client.js         # REST API client with JWT handling
│   │   ├── context/AuthContext.jsx
│   │   ├── components/           # Sidebar, ScoreGauge, SeverityBadge
│   │   ├── pages/                # AuthPage, OverviewPage, NewScanPage, ScanDetailsPage, ScanHistoryPage
│   │   ├── App.jsx
│   │   └── index.css
│   ├── package.json
│   └── vite.config.js
├── deployment/
│   ├── nginx.conf                # Nginx reverse proxy config
│   ├── gunicorn.conf.py          # Production Gunicorn worker config
│   └── aws-deployment.md         # AWS EC2, S3, IAM, CloudWatch setup guide
├── sample-project/               # Safe synthetic demo fixture files (triggers findings)
├── sample-project.zip            # Ready-to-upload demo archive (Critical findings demo)
├── clean-sample-project/         # Clean reference project (follows security best practices)
├── clean-sample-project.zip      # Ready-to-upload clean archive (100/100 score demo)
├── package_sample.py             # Script to regenerate sample archives
├── .env.example
├── .gitignore
└── README.md
```

---

## Local Quickstart Guide

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Node.js 18+ and npm

### 2. Backend Setup

```bash
# 1. Clone repository
git clone <repository-url>
cd "Secrets Detection"

# 2. Configure environment
cp .env.example .env

# 3. Install Python dependencies
pip install -r backend/requirements.txt

# 4. Generate dataset and train the Random Forest ML model
python ml/generate_dataset.py
python ml/train_model.py
```

### 3. Running the Application

You can run the backend and frontend simultaneously:

**Terminal 1 — Flask API Server:**
```bash
python backend/run.py
# Server starts at http://127.0.0.1:5000
# Also serves the built frontend at http://127.0.0.1:5000 if frontend/dist exists
```

**Terminal 2 — React / Vite Development Server:**
```bash
cd frontend
npm install
npm run dev
# Dev server runs at http://localhost:3000 (proxies /api to Flask)
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Machine Learning Component

The machine learning component is a required core element of CloudGuard. It evaluates candidates using 14 engineered features:

1. `length`: String character count
2. `entropy`: Shannon entropy $H = -\sum p_i \log_2(p_i)$
3. `uppercase_ratio`, `lowercase_ratio`, `digit_ratio`, `special_ratio`
4. `unique_char_ratio`: Unique characters divided by total length
5. `has_uppercase`, `has_lowercase`, `has_digits`, `has_special_chars`
6. `has_known_prefix`: Binary indicator for known secret prefixes
7. `context_keyword_score`: Proximity score based on variable/key name
8. `is_quoted_value`: Whether the candidate was assigned within quotes

### Actual Evaluation Results (`ml/evaluation/metrics.json`):
- **Model:** `RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)`
- **Dataset:** 3,000 synthetic samples (1,500 secrets, 1,500 benign)
- **Train/Test Split:** 80% train, 20% test (stratified)
- **Precision:** `1.0000`
- **Recall:** `0.9967`
- **F1 Score:** `0.9983`
- **Accuracy:** `0.9983`
- **Confusion Matrix:** True Negatives: 300, False Positives: 0, False Negatives: 1, True Positives: 299

---

## Running Automated Tests

CloudGuard has a comprehensive test suite covering all security, archive validation, machine learning, and API requirements:

```bash
python -m pytest backend/tests/ -v
```

### Test Suite Coverage:
- `test_archive.py`: Valid ZIP extraction, non-ZIP rejection, corrupt archive defense, entry-count limits, uncompressed byte limits, path traversal blocking (`../../`), and binary file skipping.
- `test_auth.py`: User registration, password hashing verification, email validation, duplicate prevention, JWT token issuance, and protected route access.
- `test_health.py`: Operational health check endpoint (`/api/health`).
- `test_ml.py`: Feature extraction across edge cases, model inference, prediction dictionary formats, and missing model error handling.
- `test_rules_masking.py`: Regex rule matching for AWS keys, GitHub tokens, database URIs, passwords, private keys, JWTs; Shannon entropy verification; candidate extraction; and strict secret masking.
- `test_scans_dashboard.py`: End-to-end scan execution, security score deduction calculation, detection method attribution (`Rule`, `ML`, `Rule + ML`), cross-user authorization barriers (403 Forbidden), dashboard aggregations, and scanning `sample-project.zip`.

---

## Step-by-Step Demonstration Walkthrough

1. **Start Servers:** Ensure Flask and Vite are running. Open [http://localhost:3000](http://localhost:3000).
2. **Register Account:** Click **Create Account**, enter your name, email (`demo@example.com`), and a password (`Password123!`).
3. **Overview Dashboard:** Note the initial empty dashboard showing 0 scans and an empty history table.
4. **Initiate Scan:** Click **New Scan** in the sidebar.
5. **Upload Archive:**
   - **Scenario A (Critical Findings Demo):** Upload `sample-project.zip` to demonstrate rule detection, ML classification, masked previews, and severity deductions.
   - **Scenario B (Clean Project Demo):** Upload `clean-sample-project.zip` to demonstrate a clean repository following best practices resulting in 0 findings and a **100/100 Security Score**.
6. **Execute Scan:** Click **Start Scan**. Observe the scanning pipeline progress indicators as files are extracted, rules are evaluated, and the Random Forest model performs inference.
7. **Inspect Scan Report:**
   - Review the calculated **Security Score** (e.g. Critical risk score).
   - Observe findings categorized by severity: **AWS Secret Key (Critical)**, **GitHub Token (Critical)**, **Database Connection URI (Critical)**, **AWS Access Key ID (High)**, and **JWT Token (Medium)**.
   - Note the **Detection Method** column distinguishing `Rule`, `ML`, and `Rule + ML`.
   - Click any finding row to expand the drawer: view the **Masked Evidence** (e.g., `AKIA****MPLE`, raw secret is never shown), detection reason, and concrete remediation steps.
8. **Revisit History:** Click **Scan History** in the sidebar to verify your completed scan is permanently recorded and accessible.

---

## Security & Privacy Compliance

- **No Code Execution:** Files are parsed as text; no uploaded files are ever imported, executed, or compiled.
- **Decompression Bomb Protection:** Hard entry limits (1,000 files) and uncompressed byte limits (100 MB).
- **Safe Storage:** Uploads stored in private S3 buckets with SSE-S3 encryption in AWS mode; local temporary directories are purged in `finally` blocks.
- **Masking:** Only masked previews (first and last characters with `****` padding) are stored or transmitted.
- **IAM Least Privilege:** Dedicated IAM policies grant only `s3:PutObject`, `s3:GetObject`, and `s3:DeleteObject` for the application's prefix.
- **Ownership Verification:** Every scan and finding lookup strictly enforces `scan.user_id == current_user.id`.

