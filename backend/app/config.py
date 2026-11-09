import os
import tempfile
from pathlib import Path
from dotenv import load_dotenv

# Load root .env if present
root_dir = Path(__file__).resolve().parent.parent.parent
load_dotenv(root_dir / ".env")


class Config:
    """Base application configuration loaded from environment variables."""
    ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = ENV == "development"
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "default-insecure-flask-secret-key-replace")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default-insecure-jwt-secret-key-replace")
    
    # Database
    # Support both sqlite:/// and mysql+pymysql://
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{root_dir / 'cloudguard.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Storage
    STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "local").lower()
    AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
    S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "cloudguard-uploads")
    
    # Optional SNS Notifications
    ENABLE_SNS = os.getenv("ENABLE_SNS", "false").lower() in ("true", "1", "yes")
    SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")
    
    # Upload limits
    UPLOAD_MAX_MB = int(os.getenv("UPLOAD_MAX_MB", "25"))
    MAX_CONTENT_LENGTH = UPLOAD_MAX_MB * 1024 * 1024  # Flask request body limit
    
    MAX_ARCHIVE_UNCOMPRESSED_MB = int(os.getenv("MAX_ARCHIVE_UNCOMPRESSED_MB", "100"))
    MAX_ARCHIVE_UNCOMPRESSED_BYTES = MAX_ARCHIVE_UNCOMPRESSED_MB * 1024 * 1024
    MAX_ARCHIVE_FILES = int(os.getenv("MAX_ARCHIVE_FILES", "1000"))
    PER_FILE_MAX_BYTES = int(os.getenv("PER_FILE_MAX_BYTES", str(5 * 1024 * 1024))) # 5MB per file
    
    # ML model path
    ML_MODEL_PATH = os.getenv("ML_MODEL_PATH", str(root_dir / "ml" / "models" / "secret_classifier.joblib"))
    
    # Local temporary upload directory (in OS temp directory to prevent watchdog reload loops)
    LOCAL_UPLOAD_DIR = os.getenv("LOCAL_UPLOAD_DIR", str(Path(tempfile.gettempdir()) / "cloudguard_scans"))


class TestConfig(Config):
    """Configuration for automated testing."""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    STORAGE_BACKEND = "local"
    UPLOAD_MAX_MB = 10
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    MAX_ARCHIVE_UNCOMPRESSED_MB = 20
    MAX_ARCHIVE_UNCOMPRESSED_BYTES = 20 * 1024 * 1024
    MAX_ARCHIVE_FILES = 100

