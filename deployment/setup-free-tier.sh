#!/bin/bash
# ==============================================================================
# CloudGuard — 100% Free-Tier Automated EC2 Setup Script
# ==============================================================================
# Compatible with Ubuntu 22.04 LTS / 24.04 LTS on t2.micro or t3.micro.
# Cost: $0 (Uses standard AWS Free Tier allowances, no paid services).
# ==============================================================================

set -e

echo ">>> [1/7] Initializing CloudGuard Free-Tier Setup..."
export DEBIAN_FRONTEND=noninteractive

# 1. Setup 2GB Swap space (CRITICAL for t2.micro/t3.micro 1GB RAM instances to prevent OOM)
if [ ! -f /swapfile ]; then
    echo ">>> Creating 2GB swap file to prevent memory exhaustion..."
    fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo ">>> Swap configuration complete."
fi

# 2. Update packages and install core dependencies
echo ">>> [2/7] Installing system dependencies (Python, Node.js, Nginx)..."
apt-get update -y
apt-get install -y python3 python3-pip python3-venv git nginx curl ufw

# Install Node.js 20.x LTS
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
fi

# 3. Setup Project Directory
APP_DIR="/home/ubuntu/cloudguard"
REPO_URL="https://github.com/PravarKhandelwal16/CloudGuard.git"

echo ">>> [3/7] Setting up application repository in $APP_DIR..."
if [ ! -d "$APP_DIR" ]; then
    git clone "$REPO_URL" "$APP_DIR"
    chown -R ubuntu:ubuntu "$APP_DIR"
else
    cd "$APP_DIR"
    git pull origin main || true
fi

cd "$APP_DIR"

# 4. Generate Production .env with Strong Random Secrets
echo ">>> [4/7] Generating configuration and secrets..."
if [ ! -f "$APP_DIR/.env" ]; then
    FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    
    cat <<EOF > "$APP_DIR/.env"
FLASK_ENV=production
FLASK_SECRET_KEY=$FLASK_SECRET
JWT_SECRET_KEY=$JWT_SECRET
DATABASE_URL=sqlite:////home/ubuntu/cloudguard/cloudguard.db
STORAGE_BACKEND=local
AWS_REGION=ap-south-1
UPLOAD_MAX_MB=25
MAX_ARCHIVE_UNCOMPRESSED_MB=100
MAX_ARCHIVE_FILES=1000
ML_MODEL_PATH=/home/ubuntu/cloudguard/ml/models/secret_classifier.joblib
EOF
    chown ubuntu:ubuntu "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo ">>> Generated secure .env file."
fi

# 5. Build Python Virtual Environment
echo ">>> [5/7] Installing Python requirements and Gunicorn..."
sudo -u ubuntu python3 -m venv "$APP_DIR/venv"
sudo -u ubuntu "$APP_DIR/venv/bin/pip" install --upgrade pip
sudo -u ubuntu "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/backend/requirements.txt"
sudo -u ubuntu "$APP_DIR/venv/bin/pip" install gunicorn

# 6. Build React Frontend
echo ">>> [6/7] Building React production distribution..."
cd "$APP_DIR/frontend"
sudo -u ubuntu npm install
sudo -u ubuntu npm run build
cd "$APP_DIR"

# 7. Configure Nginx and Systemd Service
echo ">>> [7/7] Configuring Systemd and Nginx web server..."
mkdir -p /var/log/cloudguard
chown -R ubuntu:ubuntu /var/log/cloudguard

# Install systemd service
cp "$APP_DIR/deployment/cloudguard.service" /etc/systemd/system/cloudguard.service
systemctl daemon-reload
systemctl enable cloudguard
systemctl restart cloudguard

# Install Nginx site configuration
cp "$APP_DIR/deployment/nginx.conf" /etc/nginx/sites-available/cloudguard
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/cloudguard /etc/nginx/sites-enabled/cloudguard
nginx -t
systemctl restart nginx

PUBLIC_IP=$(curl -s https://checkip.amazonaws.com || curl -s https://ifconfig.me || echo "your-server-ip")

echo "=============================================================================="
echo ">>> CloudGuard Deployment Successful! (100% Free Tier)"
echo ">>> Open your browser to: http://$PUBLIC_IP"
echo "=============================================================================="
