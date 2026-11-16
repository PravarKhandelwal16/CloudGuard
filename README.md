# CloudGuard — Cloud-Based Secrets Leakage Detection and Security Analysis System

[![Tests](https://img.shields.io/badge/tests-43%20passed-success.svg)](#running-automated-tests)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](#technology-stack)
[![React](https://img.shields.io/badge/frontend-React%20%2B%20Vite-61dafb.svg)](#technology-stack)
[![ML](https://img.shields.io/badge/ML-Random%20Forest%20Classifier-orange.svg)](#machine-learning-component)
[![AWS](https://img.shields.io/badge/AWS-STS%20AssumeRole%20%7C%20Read--Only-232f3e.svg)](#cloudguard-cloud-security-auditor)

CloudGuard is a comprehensive cloud and application security platform offering two primary security capabilities:

1. **Source Code Secret Scanner:** Safely inspects source code archives for exposed credentials using modular **pattern matching**, **Shannon entropy heuristics**, and a trained **Random Forest machine learning classifier** (`scikit-learn`).
2. **CloudGuard Cloud Security Auditor:** Assesses live AWS cloud infrastructure (or realistic simulated environments) for common security misconfigurations across **S3**, **IAM**, **Security Groups**, **CloudTrail**, and **Storage Encryption (EBS/RDS)**, generating actionable remediation playbooks and calculating an infrastructure posture score.

---

## Dual Architecture Overview

```text
                                     Developer / Security Auditor
                                                  |
                                                  v
                                        React Web Dashboard
                             (Secrets Detection & Cloud Security Auditor)
                                                  |
                                             HTTPS / REST
                                                  |
                                                  v
                                            Flask Backend
                    +-----------------------------+-----------------------------+
                    |                                                           |
                    v                                                           v
       [Module 1: Secret Scanner]                                 [Module 2: Cloud Auditor]
                    |                                                           |
         Safe Archive Inspection                                   AWS STS AssumeRole / Simulation
         (Zip-bomb / Traversal defense)                            (Temporary Read-Only Credentials)
                    |                                                           |
      Candidate Extraction & Entropy                               Modular Security Rules Engine
                    |                                              (S3, IAM, SGs, CloudTrail, Storage)
        +-----------+-----------+                                               |
        |                       |                                   Severity & Scoring Engine
        v                       v                                 (Deductions, Coverage, Limitation Notes)
   Rule Engine             Random Forest                                        |
  (Regex match)            (14 Features)                                        v
        |                       |                                  Cloud Assessment Findings &
        +-----------+-----------+                                  Remediation Playbooks
                    |                                                           |
                    v                                                           v
       Masked Findings & Risk Score                                Masked Findings & Score
                    |                                                           |
                    +-----------------------------+-----------------------------+
                                                  |
                                                  v
                                      Database Persistence (SQLite/MySQL)
                                      (Zero Credentials / Zero Raw Secrets)
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

## CloudGuard Cloud Security Auditor

The **CloudGuard Cloud Security Auditor** extends CloudGuard from static source-code analysis to cloud infrastructure posture management (CSPM). It inspects AWS environments for misconfigurations, assesses risk in context, calculates a dedicated Cloud Security Score, and provides step-by-step console and CLI remediation playbooks.

### 1. Key Capabilities & Checks Implemented

The modular security rules engine evaluates 5 critical AWS categories:

| Service / Domain | Security Checks Implemented | Severity | Boto3 APIs Used |
|---|---|---|---|
| **S3 Buckets** | • Publicly accessible S3 buckets<br>• Incomplete/disabled S3 Block Public Access<br>• Missing server-side default encryption (SSE)<br>• Insecure bucket policies & public ACLs | **CRITICAL** / **HIGH** / **MEDIUM** | `list_buckets`<br>`get_public_access_block`<br>`get_bucket_policy_status`<br>`get_bucket_encryption`<br>`get_bucket_acl` |
| **IAM Security** | • Full administrative wildcard policies (`Action: *`, `Resource: *`)<br>• Direct `AdministratorAccess` attached to IAM users<br>• Sensitive service wildcards (`iam:*`, `kms:*`, `sts:*`)<br>• Inline and managed policy analysis | **HIGH** / **MEDIUM** | `list_users`<br>`list_roles`<br>`list_policies`<br>`get_policy`<br>`get_policy_version`<br>`list_attached_user_policies`<br>`get_user_policy`<br>`get_role_policy` |
| **Security Groups** | • Inbound SSH (Port 22) exposed to `0.0.0.0/0` or `::/0`<br>• Inbound RDP (Port 3389) exposed to `0.0.0.0/0` or `::/0`<br>• All ports / protocols open (`-1` or `0-65535`)<br>• Database ports (3306, 5432, 27017) exposed to internet | **CRITICAL** / **HIGH** | `describe_security_groups` |
| **CloudTrail** | • No multi-region trail configured in AWS account<br>• Trails that have stopped logging (`IsLogging=False`)<br>• Log file integrity validation disabled<br>• Missing customer-managed KMS key encryption | **HIGH** / **LOW** | `describe_trails`<br>`get_trail_status` |
| **Storage Encryption** | • Unencrypted EBS volumes at rest<br>• Unencrypted RDS database instances | **MEDIUM** | `describe_volumes`<br>`describe_db_instances` |

---

### 2. Secure Cross-Account Access Architecture

CloudGuard enforces strict cloud credential hygiene:
- **No Permanent Keys:** Users never supply `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY`.
- **Zero Credential Persistence:** Temporary credentials received from STS AssumeRole are held exclusively in volatile memory for the duration of the scan and never stored in the database or logged.
- **Strict Read-Only Guarantee:** The application only calls read-only APIs (`describe_*`, `get_*`, `list_*`). **CloudGuard NEVER modifies, deletes, disables, or reconfigures AWS resources.**
- **Session Duration:** Temporary session credentials are automatically set to a 900-second (15-minute) expiration.

#### Sample IAM Trust Policy (Customer Account)
To allow CloudGuard to audit an AWS account, create an IAM role (e.g. `CloudGuardAuditorRole`) with this trust relationship:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<CLOUDGUARD-ACCOUNT-ID>:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "optional-custom-external-id"
        }
      }
    }
  ]
}
```

#### Required Read-Only IAM Permissions Policy
Attach the AWS-managed `SecurityAudit` policy, or use this scoped policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetEncryptionConfiguration",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

---

### 3. Local Simulation Mode (Mandatory Demo Mode)

CloudGuard includes a built-in **Local Simulation Mode** that allows full testing and demonstration of the auditor without requiring a real AWS account or incurring any cloud charges:
- Backed by realistic multi-service JSON fixtures (`backend/app/cloud_security/fixtures/sample_aws_data.json`).
- Runs through the **exact same security rules engine and scoring logic** as live scans.
- Clearly watermarked with:
  > **`"DEMO / SIMULATED DATA — NOT LIVE AWS FINDINGS"`**

---

### 4. Cloud Security Scoring & Coverage Methodology

The Cloud Security Score operates on a transparent, deduction-based model:

$$\text{Cloud Security Score} = \max(0, 100 - \sum \text{Deductions})$$

- **Critical:** -30 points (e.g. Unrestricted internet inbound to all ports, Public S3 bucket)
- **High:** -15 points (e.g. SSH/RDP open to 0.0.0.0/0, IAM full administrative wildcard, CloudTrail not logging)
- **Medium:** -7 points (e.g. S3 default encryption missing, EBS/RDS unencrypted, broad service wildcards)
- **Low:** -2 points (e.g. CloudTrail log file validation disabled)
- **Informational / Passed:** 0 points (Baseline security controls met)

#### Honest Incomplete Assessment Handling
If AWS IAM permissions are missing (e.g. API returns `AccessDenied`) or resources could not be evaluated, CloudGuard:
1. Marks the affected check as **`NOT ASSESSED`** or **`WARNING`**.
2. Flags the assessment coverage status as **`incomplete`**.
3. Clearly documents the missing permissions in `coverage_notes` rather than falsely marking resources as secure.

---

### 5. Cloud Security REST API Endpoints

All endpoints require JWT Bearer authentication (`@login_required`):

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/cloud-security/connect` | Save or update AWS account connection details (account ID, role ARN, region) |
| `POST` | `/api/cloud-security/test-connection` | Validate STS AssumeRole access and test connectivity |
| `POST` | `/api/cloud-security/scan` | Execute live AWS assessment using temporary STS credentials |
| `POST` | `/api/cloud-security/demo-scan` | Execute local simulation assessment with sample fixtures |
| `GET` | `/api/cloud-security/scan/<scan_id>` | Retrieve full assessment report, findings, evidence, and scores |
| `GET` | `/api/cloud-security/history` | List previous cloud security scans for the authenticated user |
| `GET` | `/api/cloud-security/findings/<id>` | Retrieve detailed finding evidence and step-by-step remediation guide |
| `GET` | `/api/cloud-security/summary` | Aggregate summary of posture, latest score, and connected accounts |

---

### 6. Cost Considerations & AWS Pricing Disclaimer

> [!NOTE]
> CloudGuard only performs read-only `Describe*`, `Get*`, and `List*` AWS API calls. Under AWS standard pricing:
> - Most `Describe` and `Get` management API calls (EC2, S3, IAM, CloudTrail, RDS) fall well within the AWS Free Tier and standard API call allowances.
> - However, frequent API calls on very large accounts or outside free tiers may incur nominal AWS API request charges.
> - **CloudGuard never provisions, modifies, or deletes AWS resources, guaranteeing no infrastructure provisioning costs.**

---

## Running Automated Tests

CloudGuard includes a test suite covering all security, archive validation, machine learning, cloud security checks, and API requirements:

```bash
python -m pytest backend/tests/ -v
```

### Test Suite Coverage (43 Tests Total):
- `test_archive.py`: Valid ZIP extraction, non-ZIP rejection, corrupt archive defense, entry-count limits, uncompressed byte limits, path traversal blocking (`../../`), and binary file skipping (7 tests).
- `test_auth.py`: User registration, password hashing verification, email validation, duplicate prevention, JWT token issuance, and protected route access (6 tests).
- `test_health.py`: Operational health check endpoint `/api/health` (1 test).
- `test_ml.py`: Feature extraction across edge cases, model inference, prediction dictionary formats, and missing model error handling (3 tests).
- `test_rules_masking.py`: Regex rule matching for AWS keys, GitHub tokens, database URIs, passwords, private keys, JWTs; Shannon entropy verification; candidate extraction; and strict secret masking (9 tests).
- `test_scans_dashboard.py`: End-to-end secret scan execution, security score deduction calculation, detection method attribution (`Rule`, `ML`, `Rule + ML`), cross-user authorization barriers (403 Forbidden), and dashboard aggregations (5 tests).
- `test_cloud_security.py`: **(New Cloud Security Auditor Suite - 12 tests)**
  - S3 public bucket & Block Public Access detection
  - S3 default encryption missing detection
  - IAM wildcard administrative privilege detection
  - Security Group SSH (port 22) exposure detection
  - Security Group RDP (port 3389) exposure detection
  - CloudTrail logging stopped & multi-region trail detection
  - EBS & RDS storage encryption detection
  - Contextual severity classification & score deduction calculation
  - Honest incomplete assessment handling on `AccessDenied`
  - STS expired credentials & validation error handling
  - Local simulation mode execution without AWS credentials
  - REST API workflow (connect, test-connection, scan, demo-scan, history, findings, authorization isolation)

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

