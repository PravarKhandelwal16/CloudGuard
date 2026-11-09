# CloudGuard — Project Requirements and Implementation Guide

> **Purpose of this file:** This is the primary product and engineering brief for Antigravity. Read it before making changes. Use it as the source of truth for the first working version of CloudGuard.

## 1. Project at a glance

**Project name:** CloudGuard  
**Project type:** Cloud-based secrets leakage detection and security analysis web application  
**Primary goal:** Allow a developer to upload a ZIP archive of a source-code project, scan its files for accidentally exposed credentials, combine rule-based detection with a machine-learning classifier, and present understandable findings and remediation advice in a simple dashboard.

CloudGuard is an educational and demonstrable security tool. It is not intended to replace enterprise secret-scanning platforms or guarantee that a project is free of secrets.

### The problem

Developers sometimes commit credentials to source code or configuration files. Examples include cloud access keys, API tokens, database passwords, private keys, and authentication tokens. If exposed, these values may allow unauthorized access to systems or data.

### The proposed solution

A user uploads a project ZIP. CloudGuard safely extracts and inspects eligible text files without executing uploaded code. A detection pipeline uses:

1. **Rule-based detection** — known credential patterns, contextual keywords, and entropy/heuristic checks.
2. **Machine learning** — a Random Forest classifier evaluates candidate strings using engineered features and estimates whether each candidate is likely to be a secret.
3. **Risk assessment** — combines the detection evidence and credential type into a severity classification.
4. **Reporting** — displays masked evidence, file and line location, confidence, severity, and remediation guidance.

The first release must be a complete working application, not only a UI mock-up or a locally running scanner.

## 2. Scope and priorities

### Must be implemented in the first version

- User registration, login, and logout.
- Authenticated ZIP project upload.
- ZIP validation and safe extraction.
- Private AWS S3 storage for uploaded ZIP files when cloud mode is enabled.
- Python scanning engine.
- Rule-based secret detection.
- A trained and integrated Random Forest ML model.
- Combined detection and risk classification.
- Masked findings with file name and line number.
- A transparent security score.
- Scan history and scan-detail pages.
- A simple, responsive dashboard.
- MySQL-compatible persistence, with SQLite allowed for local development.
- AWS EC2 deployment path, IAM role-based permissions, and CloudWatch application logs.
- Automated tests for the important security and detection paths.

### Optional, only after the first version works

- AWS SNS notifications for critical findings.
- AWS Secrets Manager integration for application configuration.
- GitHub repository scanning.
- Background job queue for large or frequent scans.
- Scheduled/continuous repository monitoring.

### Explicitly out of scope for the first version

- Automatic credential rotation or deletion from a user's repository.
- Running or building uploaded source code.
- Complex multi-tenant organization management, role hierarchies, or an admin control panel.
- A complicated analytics dashboard with many charts.
- Real-time repository monitoring.
- Sending candidate secrets to third-party AI services or external APIs.

Do not add optional features at the expense of completing the core workflow.

## 3. Users and primary workflow

The primary user is a developer who wants to check a project before sharing it or deploying it.

1. The user registers or logs in.
2. The user opens **New Scan** and uploads a `.zip` file.
3. The backend validates the archive and stores the original ZIP in a private S3 bucket in cloud mode. Local development may use a local temporary directory.
4. CloudGuard safely inspects eligible files and runs the detection pipeline.
5. The backend saves the scan summary and sanitized findings in the database.
6. The user is redirected to the scan report.
7. The user can review findings, understand why each item was flagged, follow remediation guidance, and revisit the scan from scan history.

The user must never see the complete detected secret in the UI, API response, database, or application logs.

## 4. Technology stack

Use the following stack unless the existing repository already has a sound equivalent. Avoid introducing unnecessary frameworks.

| Layer | Technology | Responsibility |
|---|---|---|
| Frontend | React + Vite + JavaScript | Simple responsive web interface |
| Styling | Plain CSS or a light utility approach | Consistent, accessible UI; do not over-engineer styling |
| Backend | Python + Flask | Authentication, uploads, scan orchestration, APIs |
| ORM | Flask-SQLAlchemy / SQLAlchemy | Database access and models |
| Database | MySQL for cloud deployment; SQLite for local development | Users, scans, findings |
| Secret scanning | Python | File processing, rule matching, candidate extraction, feature engineering |
| Machine learning | scikit-learn RandomForestClassifier | Candidate classification |
| Model persistence | joblib | Save and load the trained model and preprocessing metadata |
| Cloud storage | AWS S3 | Private storage of uploaded ZIP files |
| Compute/deployment | AWS EC2 | Host Flask and the built React frontend |
| Web server | Nginx + Gunicorn | Serve frontend assets and proxy API requests to Flask |
| Access management | AWS IAM instance profile/role | Grant the EC2 application least-privilege S3 access |
| Monitoring | AWS CloudWatch | Application and deployment logs |

### Configuration principles

- Keep all credentials and environment-specific settings in environment variables.
- Provide a `.env.example` containing variable names and safe placeholder values only.
- Never commit `.env`, AWS keys, passwords, trained data containing real credentials, or private keys.
- Use an EC2 IAM role for AWS access. Do not put AWS access keys in source code or the frontend.
- Use a configuration flag such as `STORAGE_BACKEND=local|s3` so local development does not require AWS credentials.
- Use `DATABASE_URL` to select SQLite locally or MySQL in deployment.

Suggested environment variables:

```env
FLASK_ENV=development
FLASK_SECRET_KEY=replace-with-a-long-random-value
JWT_SECRET_KEY=replace-with-a-different-long-random-value
DATABASE_URL=sqlite:///cloudguard.db
STORAGE_BACKEND=local
AWS_REGION=ap-south-1
S3_BUCKET_NAME=your-private-cloudguard-bucket
UPLOAD_MAX_MB=25
MAX_ARCHIVE_UNCOMPRESSED_MB=100
MAX_ARCHIVE_FILES=1000
ML_MODEL_PATH=ml/models/secret_classifier.joblib
```

Do not use the example values as production secrets. Generate strong values for deployment.

## 5. High-level architecture

```text
                         Developer
                             |
                             v
                    React Web Application
                  (Login / Upload / Dashboard)
                             |
                         HTTPS / REST
                             |
                             v
                      Flask Backend
                  /          |          \
                 /           |           \
          Authentication  Scan Service  Database
                             |          (MySQL/SQLite)
                             |
                      Upload Validation
                             |
                      Private AWS S3
                    (cloud mode only)
                             |
                    Safe ZIP Inspection
                             |
                    Text File Processing
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
                   Sanitized DB Records
                             |
                             v
                    React Scan Report
```

### Deployment architecture

For the initial AWS deployment, keep the infrastructure understandable:

- One EC2 instance runs Nginx, the Flask application through Gunicorn, and the built React frontend.
- A private S3 bucket stores uploaded archives. Block all public access and enable server-side encryption.
- An EC2 IAM instance role grants only the required bucket/object permissions.
- MySQL can run on the same EC2 instance for a low-cost demonstration, but keep the database configuration portable so it can be moved to Amazon RDS later. Do not expose the database port publicly.
- CloudWatch receives application and system logs. Logs must not contain uploaded file contents or secret values.

This architecture is intentionally modest. Do not introduce Kubernetes, multiple microservices, Redis, or a message broker in the first version.

## 6. Core modules and implementation details

### 6.1 Authentication

Implement:

- User registration with name, email, and password.
- Login and logout.
- Password hashing with Werkzeug's secure password hashing utilities (or an equivalent modern password hash).
- Token-based authentication for the React application, preferably using secure, HTTP-only cookies where the deployment setup supports them.
- Authorization checks on every scan and finding endpoint: a user can only view their own scans and findings.
- Basic validation for email and password fields.

Do not return password hashes from any API. Do not store plaintext passwords.

### 6.2 ZIP upload and storage

Accept only ZIP archives in the first version.

Validation requirements:

- Enforce a configurable compressed upload size limit (default 25 MB).
- Validate the file extension and inspect the archive format; do not trust the browser-provided MIME type alone.
- Reject corrupt, encrypted, or unsupported archives with a clear error.
- Limit the number of archive entries (default 1,000).
- Limit total declared and actual uncompressed size (default 100 MB).
- Reject path traversal entries such as `../../outside.txt` and absolute paths.
- Reject or safely ignore symbolic links and special files.
- Do not recursively unpack nested archives in the first version.
- Do not execute, import, install, or build any uploaded file.
- Use a unique, non-user-controlled S3 object key, for example `uploads/<user-id>/<uuid>.zip`.
- S3 objects must be private, encrypted, and inaccessible through public URLs.

For the first implementation, the backend may accept the upload, store it in S3 in cloud mode, read it for scanning, and then apply a configurable retention policy. Default recommendation: keep the archive only as long as needed for scan processing and delete it after a successful scan; alternatively, retain it for a short configurable period if the demo needs re-download capability. The UI must not imply that source archives are retained indefinitely.

Local development should use a temporary directory and remove temporary files in a `finally` block, including when scanning fails.

### 6.3 File selection and safe inspection

Scan text-oriented files likely to contain source code or configuration. Use an allowlist of extensions, for example:

```text
.py .js .jsx .ts .tsx .java .go .php .rb .cs .cpp .c .h
.json .yaml .yml .toml .ini .env .conf .config .properties
.xml .sql .sh .bash .ps1 .tf .md .txt
Dockerfile (filename without a conventional extension)
```

Correct the allowlist implementation for filenames such as `Dockerfile` that may not have a conventional extension. Exclude common binary files, large generated folders, dependency folders, and version-control internals by default, for example:

```text
node_modules/ .git/ .venv/ venv/ __pycache__/ dist/ build/ target/
```

Implementation requirements:

- Read files using safe size limits and a tolerant text decoder.
- Skip binary-looking files and files above a configurable per-file limit.
- Preserve line numbers during processing.
- Normalize candidate strings for feature extraction without changing the original file.
- Avoid putting complete file contents into logs or error messages.
- Record skipped file counts/reasons in the scan summary where useful.

### 6.4 Rule-based secret detection

Create a modular rule engine. Keep patterns in a separate file or structured rule definitions so additional patterns can be added without rewriting the scanner.

The initial rules should cover these categories:

| Secret category | Detection approach | Suggested default severity |
|---|---|---|
| AWS secret access key | Contextual assignment plus high-entropy value; detect common variable names such as `AWS_SECRET_ACCESS_KEY` | Critical |
| AWS access key ID | Known AWS access-key ID format and context | High (ID alone is not a complete credential) |
| GitHub access token | Known token prefixes/patterns | Critical or High depending on rule confidence |
| Generic API key/token | Assignment/context keywords plus candidate extraction | High |
| Database connection string with embedded password | Parse connection URI and detect a password component | Critical or High |
| Generic password/secret assignment | Contextual key names such as `password`, `passwd`, `secret`, `client_secret`, `token` | High or Medium based on evidence |
| Private key material | PEM/private-key block markers | Critical |
| JWT-like token | Token structure and contextual evidence | Medium or High depending on context |

Important interpretation rules:

- An AWS access key ID by itself is not sufficient to authenticate. Do not describe it as a complete AWS credential unless a corresponding secret key is also found.
- A generic high-entropy string is not automatically a secret. Use context and ML evidence to reduce false positives.
- Do not claim that a value is valid or active. CloudGuard detects likely exposed values; it does not test them against external services.
- Make rules explainable. Each finding should include the rule name and a short reason, such as `Matched AWS secret-key assignment pattern`.

### 6.5 Candidate extraction and entropy analysis

Create a dedicated candidate-extraction layer. It should collect plausible values from:

- Values assigned to suspicious variable names.
- Known provider-specific token patterns.
- Quoted and unquoted values in common configuration formats.
- High-entropy strings within reasonable length bounds.
- Credential-like values in connection strings and headers.

Calculate Shannon entropy for candidate strings. Entropy is a feature, not a verdict. A random-looking value may be an identifier, hash, checksum, or test fixture rather than a credential.

Avoid sending entire source files to the ML model. The classifier should receive engineered numeric/categorical features derived from candidate strings and limited context.

### 6.6 Machine-learning component — required

The ML component is part of the first release. Implement it as a separate, testable module, not as code embedded in a Flask route.

**Initial algorithm:** `RandomForestClassifier` from scikit-learn.

**Task:** Binary classification of a candidate string as:

- `likely_secret` (label `1`)
- `likely_not_secret` (label `0`)

The ML model supplements rule-based scanning. It must not replace known-format detection rules.

#### Feature engineering

At minimum, calculate the following features for each candidate:

| Feature | Description |
|---|---|
| `length` | Number of characters in the candidate |
| `entropy` | Shannon entropy of the candidate |
| `uppercase_ratio` | Proportion of uppercase letters |
| `lowercase_ratio` | Proportion of lowercase letters |
| `digit_ratio` | Proportion of digits |
| `special_ratio` | Proportion of non-alphanumeric characters |
| `unique_char_ratio` | Unique characters divided by total length |
| `has_uppercase` | Whether uppercase characters are present |
| `has_lowercase` | Whether lowercase characters are present |
| `has_digits` | Whether digits are present |
| `has_special_chars` | Whether special characters are present |
| `has_known_prefix` | Whether the value resembles a known token prefix |
| `context_keyword_score` | A small numeric score based on nearby variable/assignment names, without storing full source text |
| `is_quoted_value` | Whether the candidate was extracted from a quoted assignment |

Use safe handling for empty/very short strings and avoid leaking raw candidates into training logs.

#### Training data

- Create a reproducible training pipeline, such as `ml/train_model.py`.
- Start with synthetic, clearly labeled examples. Include both secret-like values and benign values that could otherwise cause false positives (UUIDs, hashes, commit IDs, random test strings, ordinary configuration values, sample placeholders, and words).
- Do not use real personal credentials, live production keys, or any secret copied from a real repository as training data.
- If an external public dataset is added later, verify its license and ensure it does not contain usable credentials. Prefer sanitized or synthetic data.
- Keep dataset generation, feature extraction, training, evaluation, and model saving reproducible.
- Save the model using `joblib` into `ml/models/`. Do not commit a huge dataset or real secret samples.
- Include a short README explaining how to regenerate the synthetic training set and train the model.

#### Evaluation

Use a stratified train/test split and report:

- Precision
- Recall
- F1-score
- Confusion matrix
- Accuracy (as a supplementary metric only)

For security scanning, false negatives matter, but excessive false positives make the tool unusable. Discuss the precision/recall trade-off and select a probability threshold using validation results. Do not report fabricated model metrics. Display actual metrics generated by the training script in a local evaluation report.

#### Inference and integration

- Create a module such as `ml/predictor.py` that loads the trained model once and exposes a predictable function such as `predict_candidate(candidate, context)`. Internally it should call the shared feature extractor.
- The inference module should return the predicted label and probability/confidence, not the raw candidate value.
- The Flask scanner should call the module through a service layer.
- If the model file is missing or cannot load, return an explicit configuration error in development. Do not silently pretend ML ran. A clearly documented rule-only fallback may be enabled for local development, but the scan result must state that ML was unavailable.
- Unit tests must verify the feature calculations, model loading, and prediction response format.

### 6.7 Combining rules and ML

Create a result-correlation layer that combines rule evidence and ML predictions. Avoid treating the ML probability as the only source of truth.

Recommended initial decision policy:

1. A high-confidence known-format rule match remains a finding even if the ML model predicts `likely_not_secret`.
2. A candidate found only through heuristics/entropy should become a finding only when ML confidence meets the selected threshold and contextual evidence is adequate.
3. Contextual password/token assignments may be reported even if they do not match a provider-specific format, with an appropriate confidence and severity.
4. Deduplicate repeated detections of the same candidate within the same file and line range.
5. Preserve the detection method on each finding: `Rule`, `ML`, or `Rule + ML`.

Show a confidence value in the report as a rounded percentage. Label it **detection confidence**, not proof that a credential is active or compromised.

### 6.8 Severity and security score

Use a transparent, easy-to-explain scoring method. Keep the scoring logic in one module and document it in the UI.

Suggested default severity weights:

| Severity | Points deducted per finding |
|---|---:|
| Critical | 30 |
| High | 15 |
| Medium | 7 |
| Low | 2 |

**Security score formula:**

```text
Security Score = max(0, 100 - total severity deductions)
```

The score is a simple project health indicator for demonstration, not a formal security rating. Show the deduction logic in a small tooltip or explanatory note.

Suggested severity mapping:

- **Critical:** private key material, high-confidence cloud secret key, or exposed credential with strong evidence.
- **High:** likely API token, database password, or sensitive token with strong contextual evidence.
- **Medium:** ambiguous credential-like value, JWT-like value with limited context, or access-key identifier without the corresponding secret.
- **Low:** weak or low-confidence indicator worth reviewing.

Keep severity configurable by rule. The report must distinguish a confirmed pattern match from an ML/heuristic suspicion.

### 6.9 Findings and remediation guidance

Each finding should contain:

- Secret category/type.
- Severity.
- Detection method (`Rule`, `ML`, `Rule + ML`).
- Detection confidence.
- Relative file path inside the uploaded archive.
- Line number (when available).
- Masked value preview only, such as `AKIA****WXYZ` or `********`.
- Short reason for detection.
- Recommended remediation.

Never store or return the complete candidate secret. Do not include it in frontend error messages, logs, analytics, URLs, or exception traces.

Recommended generic remediation:

1. Remove the exposed value from the source code and prevent it from being committed again.
2. Rotate or revoke the credential through the provider if it may have been exposed. Deleting it from the latest file does not invalidate a leaked credential.
3. Move application secrets to environment-specific secure configuration or a managed secret store such as AWS Secrets Manager.
4. Add an appropriate ignore rule and a pre-commit or CI secret scan to reduce recurrence.
5. If the project was public, review relevant access logs and permissions.

Do not automatically rotate, revoke, or test credentials.

## 7. Simple dashboard and user interface

The dashboard must be clean, restrained, and easy to explain in a faculty presentation. It is a security overview, not a full enterprise security operations center.

### Design direction

- Professional, minimal, and consistent.
- Use a light background, dark readable text, and one restrained accent color.
- Avoid neon colors, excessive gradients, decorative animations, dense charts, and unnecessary widgets.
- Use clear labels and plain language.
- Responsive layout for laptop and mobile widths.
- Keep navigation limited to the main actions.
- Include loading, empty, success, and error states.
- Use accessible contrast, keyboard focus, and readable font sizes.

### Main navigation

Use a small left sidebar on desktop or a compact top navigation on mobile with:

- **Overview**
- **New Scan**
- **Scan History**
- **Logout**

Do not create a complex admin navigation area.

### Page 1 — Login / Register

A straightforward form with email and password, plus a link to switch between login and registration. Keep the page visually consistent with the app.

### Page 2 — Overview dashboard

Display only the following key elements:

1. Four small summary cards:
   - Total scans
   - Total findings
   - Critical findings
   - Latest security score (or `—` when no scan exists)
2. A prominent **New Scan** action.
3. A **Recent Scans** table with project/archive name, scan date, security score, finding count, and status.
4. A small **Recent High-Risk Findings** list showing category, severity, and file path (masked evidence only).

Do not add complex charts in the first version. If a visual is genuinely useful, a simple severity count bar is sufficient, but it is optional.

### Page 3 — New Scan

- One clear ZIP upload area.
- Display accepted file type and maximum file size.
- Show the selected filename and upload progress/loading state.
- Show validation errors in plain language.
- Provide one **Start Scan** button.
- Do not ask for unnecessary project configuration.

### Page 4 — Scan Report / Scan Details

At the top, show:

- Project/archive name.
- Scan date and status.
- Security score out of 100.
- Total findings and counts by Critical, High, Medium, and Low.

Below, show a simple findings table:

| Type | Severity | File | Line | Method | Confidence |
|---|---|---|---:|---|---:|

Each row can expand or open a detail panel containing the masked preview, detection reason, and remediation recommendation. Never reveal the complete secret.

Add a small note explaining that findings are potential exposed credentials and should be reviewed. Provide a clear route back to dashboard/history.

### Page 5 — Scan History

A simple table of the user's previous scans, newest first, with a link to each report. Include a helpful empty state for a new user.

### Keep the demo easy to explain

The complete demonstration should be explainable in this sequence:

1. Log in.
2. Upload a sample project ZIP containing safe dummy credentials.
3. Start a scan.
4. Show that the rules and ML model both participate in detection.
5. Open the report and explain the severity, confidence, masked evidence, and score.
6. Return to the dashboard and show the scan in history.

Use only fake demonstration credentials, clearly marked as dummy values. Never use real keys in screenshots or presentations.

## 8. Backend API design

Use REST endpoints with consistent JSON responses and appropriate HTTP status codes. Prefix endpoints with `/api`.

Suggested endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/auth/register` | Create a user account |
| POST | `/api/auth/login` | Authenticate a user |
| POST | `/api/auth/logout` | End the user session |
| GET | `/api/auth/me` | Return the current user's safe profile |
| POST | `/api/scans` | Upload and scan a ZIP archive |
| GET | `/api/scans` | List the current user's scans |
| GET | `/api/scans/<scan_id>` | Get one scan summary and sanitized findings |
| GET | `/api/dashboard/summary` | Return dashboard summary data |
| GET | `/api/health` | Application health check (no secrets/config dump) |

The scan endpoint can be synchronous for the first version because the upload and archive limits are intentionally small. Return a clear loading state in the UI while it runs. Keep the scan service isolated so a background job system can be added later without redesigning the detection engine.

### API response rules

- Use a consistent shape, for example `{ "success": true, "data": ..., "message": "..." }`.
- Return validation messages that are useful but do not reveal filesystem paths, secret values, stack traces, or cloud credentials.
- Paginate scan history if needed; do not return every finding from every scan on the dashboard.
- Validate ownership of the scan before returning its details.
- Never include raw candidate values in responses.

## 9. Database design

Use SQLAlchemy models and migrations where practical. Keep the schema small.

### `users`

| Column | Type / notes |
|---|---|
| `id` | Primary key |
| `name` | User display name |
| `email` | Unique, indexed |
| `password_hash` | Hashed password only |
| `created_at` | UTC timestamp |

### `scans`

| Column | Type / notes |
|---|---|
| `id` | Primary key; UUID or safe public identifier is preferred |
| `user_id` | Foreign key to users |
| `original_filename` | Sanitized display filename, not a filesystem path |
| `s3_object_key` | Nullable; private object key only, never a public URL |
| `status` | `completed` or `failed` for the synchronous first version; may later include `processing` |
| `security_score` | Integer from 0 to 100 |
| `total_findings` | Integer |
| `critical_count` | Integer |
| `high_count` | Integer |
| `medium_count` | Integer |
| `low_count` | Integer |
| `files_scanned` | Integer |
| `files_skipped` | Integer |
| `scan_duration_ms` | Integer |
| `ml_model_version` | Model/version identifier used for this scan |
| `created_at` | UTC timestamp |

### `findings`

| Column | Type / notes |
|---|---|
| `id` | Primary key |
| `scan_id` | Foreign key to scans |
| `category` | AWS key, API token, database password, etc. |
| `severity` | Critical / High / Medium / Low |
| `detection_method` | Rule / ML / Rule + ML |
| `confidence` | Numeric value from 0 to 1 |
| `file_path` | Relative archive path, sanitized |
| `line_number` | Nullable integer |
| `masked_preview` | Masked value only |
| `reason` | Short explanation of why it was flagged |
| `recommendation` | Remediation guidance |
| `rule_id` | Nullable rule identifier |
| `created_at` | UTC timestamp |

Do not add a `raw_secret` column. If deduplication needs a stable identifier, use a keyed HMAC digest stored only for the minimum required purpose; do not use a plain hash of a low-entropy password as a substitute for secure storage.

## 10. Suggested code organization

Adapt to the existing repository if one already exists. Keep responsibilities separated and names understandable.

```text
cloudguard/
├── README.md
├── PROJECT.md
├── .gitignore
├── .env.example
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── extensions.py
│   │   ├── models/
│   │   │   ├── user.py
│   │   │   ├── scan.py
│   │   │   └── finding.py
│   │   ├── routes/
│   │   │   ├── auth.py
│   │   │   ├── scans.py
│   │   │   └── dashboard.py
│   │   ├── services/
│   │   │   ├── storage_service.py
│   │   │   ├── scan_service.py
│   │   │   ├── archive_service.py
│   │   │   ├── detection_service.py
│   │   │   └── risk_service.py
│   │   ├── scanner/
│   │   │   ├── file_scanner.py
│   │   │   ├── candidate_extractor.py
│   │   │   ├── entropy.py
│   │   │   ├── rules.py
│   │   │   └── result_combiner.py
│   │   └── utils/
│   │       ├── masking.py
│   │       └── validation.py
│   ├── migrations/
│   ├── tests/
│   ├── requirements.txt
│   └── run.py
├── ml/
│   ├── README.md
│   ├── dataset/
│   │   └── .gitkeep
│   ├── models/
│   │   └── .gitkeep
│   ├── features.py
│   ├── generate_dataset.py
│   ├── train_model.py
│   ├── predictor.py
│   └── evaluation/
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── context/
│   │   ├── hooks/
│   │   ├── styles/
│   │   └── App.jsx
│   ├── package.json
│   └── vite.config.js
├── deployment/
│   ├── nginx.conf
│   ├── gunicorn.conf.py
│   └── aws-deployment.md
└── docs/
    ├── architecture.md
    └── api.md
```

This is a suggested structure, not a requirement to create empty files for every item. Prefer a working, coherent implementation over excessive scaffolding.

## 11. Scan pipeline — expected processing order

Implement the pipeline in a service layer, with small testable functions.

```text
1. Receive authenticated ZIP upload
2. Validate request size, file type, archive format, and archive limits
3. Create scan record
4. Store archive privately (S3 in cloud mode; temporary local storage in development)
5. Safely inspect archive entries
6. Select eligible text files and skip excluded/binary/oversized files
7. Read each eligible file and preserve line numbers
8. Apply known-format rules and contextual candidate extraction
9. Calculate candidate features, including entropy
10. Run Random Forest inference for extracted candidates
11. Combine rule and ML evidence; deduplicate findings
12. Assign category, severity, confidence, method, reason, and recommendation
13. Mask candidate previews immediately; do not persist raw candidates
14. Calculate severity counts and security score
15. Save scan summary and sanitized findings
16. Delete temporary files and apply configured S3 retention policy
17. Return sanitized scan report to the frontend
```

If any step fails, mark the scan as failed where possible, return a safe error message, and still clean up temporary files. Avoid leaving uploaded archives or partial extracted content behind.

## 12. AWS implementation requirements

### S3

- Create a dedicated bucket for CloudGuard uploads in the selected AWS region.
- Enable Block Public Access at bucket level.
- Enable server-side encryption (SSE-S3 is sufficient for the first release).
- Use unique object keys and do not use the original filename as the object key.
- Do not make objects public and do not expose bucket URLs in the frontend.
- Restrict permissions to the required bucket and object actions only.
- Apply lifecycle deletion for retained uploads if a short retention period is configured.

### IAM

Attach an IAM role/instance profile to EC2. Grant only the specific S3 actions and bucket resources the application needs, such as object upload, read, and delete. Do not use administrator access for the application role. Do not place access keys in the repository, React code, or EC2 source files.

### EC2

- Run the React production build and Flask/Gunicorn behind Nginx.
- Expose HTTPS through a suitable TLS setup; do not leave the application open over plain HTTP in a real deployment.
- Restrict SSH access and keep database ports private.
- Use environment variables or a protected server-side configuration mechanism for application secrets.
- Set request size/time limits consistently across Nginx and Flask.

### CloudWatch

Log operational events such as scan started/completed/failed, file counts, duration, and error categories. Never log file content, detected values, authentication tokens, passwords, or complete connection strings. Include a scan ID for troubleshooting without including secret material.

### SNS (optional)

Only add SNS after the core application works. If enabled, send a short notification that a scan has critical findings; do not include the secret value or full source content in the notification.

## 13. Security and privacy requirements

These are mandatory, not optional polish.

1. Never execute uploaded code or scripts.
2. Treat every uploaded archive and file as untrusted input.
3. Prevent ZIP path traversal and ZIP bombs using entry-count and uncompressed-size limits.
4. Enforce upload and per-file size limits.
5. Reject encrypted or unsupported ZIP archives with a clear message.
6. Use private S3 storage, encryption, and least-privilege IAM.
7. Keep AWS credentials and application secrets out of source code and frontend bundles.
8. Mask secrets before persistence or response generation.
9. Never log raw secrets or file contents.
10. Delete local temporary data even when errors occur.
11. Check user ownership on every scan/report request.
12. Hash passwords securely and protect authentication endpoints.
13. Use parameterized ORM/database operations.
14. Validate and sanitize filenames and archive paths before displaying them.
15. Add reasonable rate limiting to authentication and upload endpoints if practical for the first release.
16. Do not call external services to verify whether a detected credential is active.
17. Use only fake credentials for testing and demonstration.

## 14. Testing requirements

Create unit and integration tests for at least the following cases.

### Archive and upload tests

- Valid small ZIP is accepted.
- Non-ZIP and corrupt ZIP files are rejected.
- File exceeding compressed size limit is rejected.
- Archive exceeding entry count or uncompressed size limit is rejected.
- Path traversal entry is blocked.
- Encrypted ZIP is rejected or clearly reported as unsupported.
- Binary and excluded files are skipped.
- Temporary files are removed after success and failure.

### Detection tests

- Fake AWS-like key assignments are detected by the appropriate rule.
- Fake API tokens and database password assignments are detected.
- Private-key marker test fixture is detected without using a real key.
- Ordinary words, UUIDs, hashes, sample placeholders, and benign configuration values do not all become high-severity findings.
- A high-entropy value without useful context is not automatically treated as a confirmed secret.
- Line numbers are correct.
- Duplicate findings are handled predictably.
- Masking never returns the full candidate.

### ML tests

- Feature extractor handles empty, short, numeric, alphabetic, and mixed-character inputs.
- Dataset generation is reproducible with a fixed random seed.
- Training script produces a saved model and actual evaluation results.
- Predictor loads the model and returns a valid label/probability structure.
- Missing model behavior is explicit and tested.
- ML-only candidates are filtered according to the selected threshold and contextual policy.

### API and UI tests

- A user can register and log in.
- A user cannot view another user's scan.
- Upload/scan returns only masked findings.
- Dashboard summary counts match persisted data.
- Empty dashboard and empty scan history render correctly.
- Loading and error states are understandable.

## 15. Implementation phases and completion gates

Build in phases. Do not try to implement everything in one large unverified change.

### Phase 1 — Repository and application foundation

- Inspect the existing repository before editing.
- Identify existing code and retain useful working components.
- Set up Flask application factory, configuration, database connection, and health endpoint.
- Set up React/Vite, routing, shared layout, and API client.
- Add `.env.example`, `.gitignore`, and setup instructions.

**Gate:** Frontend and backend start locally; health check works; configuration is environment-driven.

### Phase 2 — Authentication and persistence

- Implement user, scan, and finding models.
- Implement registration, login, logout, and current-user endpoints.
- Protect scan routes and verify ownership.
- Create migration/setup process.

**Gate:** A user can register, log in, and access protected routes; passwords are hashed.

### Phase 3 — Upload and safe archive processing

- Build local storage mode first.
- Validate ZIP files and enforce archive limits.
- Safely select and read source/configuration files.
- Preserve file paths and line numbers.
- Clean up temporary files reliably.

**Gate:** Test ZIPs are accepted, unsafe archives are rejected, and no uploaded code is executed.

### Phase 4 — Detection engine

- Implement rules and candidate extraction.
- Implement entropy and feature calculations.
- Implement masking and finding structures.
- Test representative fake credentials and benign strings.

**Gate:** The scanner detects expected dummy cases and avoids obvious benign false positives; output is always masked.

### Phase 5 — Machine-learning model

- Generate synthetic labeled examples.
- Train and evaluate Random Forest.
- Save and load the model.
- Integrate inference into the candidate pipeline.
- Combine ML and rules using the decision policy in this brief.

**Gate:** The ML model is genuinely trained and invoked by the scan flow. Actual metrics are saved. The report identifies which method detected each finding.

### Phase 6 — Risk analysis, APIs, and reporting

- Implement severity mapping and score calculation.
- Persist sanitized findings and scan summaries.
- Implement scan upload/report/history/dashboard endpoints.

**Gate:** A complete scan can be performed through the API and revisited from history without storing raw secrets.

### Phase 7 — Frontend dashboard and workflow

- Implement login/register, overview, new scan, scan history, and report pages.
- Connect the UI to real backend APIs; do not use hardcoded mock metrics for the final workflow.
- Make loading, empty, and error states clear.
- Keep the dashboard visually simple as described in Section 7.

**Gate:** A user can complete the end-to-end demonstration entirely through the browser.

### Phase 8 — AWS integration and deployment

- Implement S3 storage adapter and test with a private bucket.
- Configure IAM instance role.
- Deploy the React build and Flask/Gunicorn behind Nginx on EC2.
- Configure database and CloudWatch logs.
- Verify that no secrets appear in logs or frontend build output.

**Gate:** The deployed application can accept a test ZIP, scan it, save the report, and show the results from the dashboard.

### Phase 9 — Final verification and documentation

- Run all tests.
- Fix security and UX issues found during verification.
- Document local setup, ML training, AWS configuration, deployment, limitations, and demo steps.
- Capture screenshots only using synthetic demo credentials.

**Gate:** A fresh developer can follow the README to run the project and reproduce a sample scan.

## 16. Demo dataset and sample project

Create a small `sample-project/` or a generated ZIP fixture for tests and demonstration. All values must be fake placeholders and visibly documented as dummy examples.

Suggested fixture files:

```text
sample-project/
├── .env.example
├── config.py
├── database.ini
├── app.js
└── README.md
```

Include a mix of:

- Fake AWS-style access key ID and secret key values.
- Fake API token assignment.
- Fake database password in a connection setting.
- Benign values such as a UUID, commit-like hash, normal URL, and placeholder text.

Do not make the fixtures look like usable credentials. Never use real credentials from AWS, GitHub, a database, or any personal account.

## 17. Non-functional requirements

- The application should be straightforward to set up on a developer machine.
- Core code should be modular and readable for a student project review.
- API and UI error messages should be understandable.
- The UI should work at common desktop and mobile widths.
- The first version should handle the defined archive limits reliably.
- Scanning should not block the UI without a visible loading state.
- No unnecessary microservices or infrastructure complexity.
- Store timestamps in UTC and format them for display in the browser.
- Keep ML inference deterministic where practical and record the model version used for each scan.

## 18. Definition of done

CloudGuard's first version is complete only when all of these statements are true:

- [ ] A user can register and log in.
- [ ] A user can upload a valid ZIP archive from the browser.
- [ ] Invalid and unsafe archives are rejected safely.
- [ ] The scanner inspects eligible files without executing them.
- [ ] Known credential patterns are detected by rules.
- [ ] Candidate strings are evaluated by a trained Random Forest model.
- [ ] Rule and ML results are combined using a documented policy.
- [ ] Findings include severity, file path, line number, method, confidence, reason, and remediation.
- [ ] The complete secret value is never displayed, persisted, or logged.
- [ ] A security score is calculated using the documented formula.
- [ ] The user can review the report and find it again in scan history.
- [ ] The dashboard contains only the simple summary cards, recent scans, and recent high-risk findings described above.
- [ ] Local development works with SQLite and local file storage.
- [ ] AWS mode works with private S3 storage and IAM role-based permissions.
- [ ] The application can be deployed on EC2 and logs can be inspected in CloudWatch.
- [ ] Tests cover archive safety, detection, ML, masking, and user ownership.
- [ ] README and ML instructions are sufficient for another developer to reproduce the demo.

## 19. Instructions specifically for Antigravity

1. **Read this complete file before coding.** Treat it as the functional specification.
2. **Inspect the current repository first.** Do not overwrite or delete existing work without understanding it. If the repository is empty, create the structure described above.
3. **Implement the actual application end to end.** Do not stop after generating a plan, static dashboard, mock API, or placeholder scanner.
4. **Build incrementally by phase.** After each phase, run the relevant tests and fix failures before moving on.
5. **Keep the dashboard simple.** Follow Section 7. Do not add features or charts that make the project harder to explain.
6. **The ML component is required.** Train a real Random Forest model from synthetic/sanitized labeled data, evaluate it, save it, and invoke it from the scan pipeline. Do not merely display an ML label in the UI.
7. **Do not fabricate model metrics or scan results.** Generate metrics from the actual training/evaluation run and findings from actual test scans.
8. **Do not expose secrets.** Mask candidates before persistence and response generation, and never log raw values.
9. **Use fake credentials only.** Do not test against real cloud accounts or third-party services.
10. **Keep AWS setup secure and understandable.** Use private S3, encryption, least-privilege IAM, and an EC2 instance role.
11. **Do not introduce unnecessary complexity.** No Kubernetes, microservices, or large asynchronous infrastructure in the MVP.
12. **Update documentation as implementation changes.** Keep README setup steps, environment variables, ML training steps, AWS deployment steps, and known limitations accurate.
13. **At the end, provide a concise implementation summary** listing what is complete, how to run it, tests executed and their results, AWS resources/configuration still required, and any known limitations. Be honest about anything not implemented.

---

## Final product statement

**CloudGuard is a cloud-based secrets leakage detection application that scans uploaded source-code projects using a hybrid of rule-based techniques and a Random Forest machine-learning classifier. It evaluates likely exposed credentials, assigns risk severity, calculates a transparent security score, and presents masked findings with remediation guidance through a simple web dashboard, while using AWS for secure storage, deployment, access control, and monitoring.**
