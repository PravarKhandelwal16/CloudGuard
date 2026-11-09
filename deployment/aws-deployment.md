# CloudGuard — AWS Deployment Guide

This guide walks through deploying CloudGuard on an **AWS EC2** instance with **Amazon S3** for secure archive storage, **AWS IAM** instance profiles for least-privilege credentials, and **Amazon CloudWatch** for application logging.

---

## 1. Amazon S3 Bucket Setup

1. **Create S3 Bucket:**
   ```bash
   aws s3api create-bucket \
     --bucket my-cloudguard-private-uploads \
     --region ap-south-1 \
     --create-bucket-configuration LocationConstraint=ap-south-1
   ```

2. **Enable Block Public Access:**
   ```bash
   aws s3api put-public-access-block \
     --bucket my-cloudguard-private-uploads \
     --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
   ```

3. **Enable Server-Side Encryption (SSE-S3):**
   ```bash
   aws s3api put-bucket-encryption \
     --bucket my-cloudguard-private-uploads \
     --server-side-encryption-configuration '{
       "Rules": [{
         "ApplyServerSideEncryptionByDefault": {
           "SSEAlgorithm": "AES256"
         }
       }]
     }'
   ```

4. **(Optional) Lifecycle Rule for Retention:**
   To automatically expire retained scan archives after 7 days:
   ```bash
   aws s3api put-bucket-lifecycle-configuration \
     --bucket my-cloudguard-private-uploads \
     --lifecycle-configuration '{
       "Rules": [{
         "ID": "DeleteOldArchives",
         "Status": "Enabled",
         "Filter": {"Prefix": "uploads/"},
         "Expiration": {"Days": 7}
       }]
     }'
   ```

---

## 2. AWS IAM Least-Privilege Role

Never use hardcoded AWS access keys. Create an IAM role for EC2:

1. **Trust Policy (`ec2-trust-policy.json`):**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": { "Service": "ec2.amazonaws.com" },
         "Action": "sts:AssumeRole"
       }
     ]
   }
   ```

2. **Permissions Policy (`s3-least-privilege.json`):**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "s3:PutObject",
           "s3:GetObject",
           "s3:DeleteObject"
         ],
         "Resource": "arn:aws:s3:::my-cloudguard-private-uploads/uploads/*"
       },
       {
         "Effect": "Allow",
         "Action": [
           "s3:ListBucket"
         ],
         "Resource": "arn:aws:s3:::my-cloudguard-private-uploads"
       }
     ]
   }
   ```

3. **Create and Attach Role:**
   ```bash
   aws iam create-role --role-name CloudGuardEC2Role --assume-role-policy-document file://ec2-trust-policy.json
   aws iam put-role-policy --role-name CloudGuardEC2Role --policy-name CloudGuardS3Policy --policy-document file://s3-least-privilege.json
   aws iam create-instance-profile --instance-profile-name CloudGuardInstanceProfile
   aws iam add-role-to-instance-profile --instance-profile-name CloudGuardInstanceProfile --role-name CloudGuardEC2Role
   aws ec2 associate-iam-instance-profile --instance-id <YOUR-EC2-INSTANCE-ID> --iam-instance-profile Name=CloudGuardInstanceProfile
   ```

---

## 3. EC2 Provisioning & Setup

- **Instance Type:** `t3.small` or `t3.medium` (Ubuntu 22.04 LTS or 24.04 LTS).
- **Security Group:**
  - Inbound Port 22: Restricted to administrator IP.
  - Inbound Port 80 & 443: Web traffic.
  - Inbound Port 3306 (MySQL): Kept internal (do not open to 0.0.0.0/0).

### On the EC2 Instance:

```bash
# Update packages
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv nodejs npm nginx git

# Clone repository
cd /home/ubuntu
git clone <repo-url> cloudguard
cd cloudguard

# Set up Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt

# Train Random Forest ML model on instance
python3 ml/generate_dataset.py
python3 ml/train_model.py

# Build React frontend
cd frontend
npm install
npm run build
cd ..

# Configure production environment variables
cat << 'EOF' > .env
FLASK_ENV=production
FLASK_SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET_KEY=$(openssl rand -hex 32)
DATABASE_URL=sqlite:////home/ubuntu/cloudguard/cloudguard.db
STORAGE_BACKEND=s3
AWS_REGION=ap-south-1
S3_BUCKET_NAME=my-cloudguard-private-uploads
UPLOAD_MAX_MB=25
MAX_ARCHIVE_UNCOMPRESSED_MB=100
MAX_ARCHIVE_FILES=1000
ML_MODEL_PATH=/home/ubuntu/cloudguard/ml/models/secret_classifier.joblib
EOF
```

---

## 4. Systemd Service & Gunicorn

Create `/etc/systemd/system/cloudguard.service`:

```ini
[Unit]
Description=CloudGuard Flask Application
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/home/ubuntu/cloudguard
Environment="PATH=/home/ubuntu/cloudguard/venv/bin"
ExecStart=/home/ubuntu/cloudguard/venv/bin/gunicorn -c deployment/gunicorn.conf.py backend.run:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo mkdir -p /var/log/cloudguard
sudo chown -R ubuntu:www-data /var/log/cloudguard
sudo systemctl daemon-reload
sudo systemctl enable cloudguard
sudo systemctl start cloudguard
```

---

## 5. Nginx Reverse Proxy & TLS

Copy the Nginx configuration:
```bash
sudo cp deployment/nginx.conf /etc/nginx/sites-available/cloudguard
sudo ln -s /etc/nginx/sites-available/cloudguard /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

Install Certbot for free HTTPS:
```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-cloudguard-domain.com
```

---

## 6. Amazon CloudWatch Logs Agent

Install the unified CloudWatch agent:
```bash
sudo apt install -y amazon-cloudwatch-agent
```

Configure `/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json` to stream logs:
```json
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/cloudguard/gunicorn_access.log",
            "log_group_name": "/cloudguard/access",
            "log_stream_name": "{instance_id}"
          },
          {
            "file_path": "/var/log/cloudguard/gunicorn_error.log",
            "log_group_name": "/cloudguard/error",
            "log_stream_name": "{instance_id}"
          }
        ]
      }
    }
  }
}
```

Start the agent:
```bash
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
```

