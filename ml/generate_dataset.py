import os
import csv
import random
import string
import uuid
from pathlib import Path
from features import extract_features, FEATURE_NAMES

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

OUTPUT_DIR = Path(__file__).resolve().parent / "dataset"
OUTPUT_CSV = OUTPUT_DIR / "synthetic_secrets_dataset.csv"


def random_string(chars: str, length: int) -> str:
    return "".join(random.choices(chars, k=length))


def generate_secrets(count=1500) -> list[tuple[str, str, bool, int]]:
    """Generates synthetic secret-like candidate examples (label=1)."""
    samples = []
    alphanumeric = string.ascii_letters + string.digits
    base64_chars = string.ascii_letters + string.digits + "/+="

    for _ in range(count):
        secret_type = random.choice([
            "aws_key", "aws_secret", "github_token", "stripe_key",
            "slack_token", "generic_api_key", "password", "jwt_token"
        ])

        is_quoted = random.choice([True, True, False])

        if secret_type == "aws_key":
            prefix = random.choice(["AKIA", "ASIA", "ABIA"])
            val = prefix + random_string(string.ascii_uppercase + string.digits, 16)
            ctx = random.choice(["AWS_ACCESS_KEY_ID", "aws_access_key", "access_key_id", "s3_key"])
        elif secret_type == "aws_secret":
            val = random_string(base64_chars, 40)
            ctx = random.choice(["AWS_SECRET_ACCESS_KEY", "aws_secret_key", "secret_access_key"])
        elif secret_type == "github_token":
            prefix = random.choice(["ghp_", "gho_", "ghu_", "ghs_"])
            val = prefix + random_string(alphanumeric, 36)
            ctx = random.choice(["GITHUB_TOKEN", "github_api_key", "gh_token", "personal_access_token"])
        elif secret_type == "stripe_key":
            val = "sk_live_" + random_string(alphanumeric, 24)
            ctx = random.choice(["STRIPE_API_KEY", "stripe_secret", "stripe_key"])
        elif secret_type == "slack_token":
            val = "xoxb-" + random_string(string.digits, 12) + "-" + random_string(alphanumeric, 24)
            ctx = random.choice(["SLACK_BOT_TOKEN", "slack_api_token"])
        elif secret_type == "generic_api_key":
            val = random_string(alphanumeric, random.randint(24, 48))
            ctx = random.choice(["api_key", "apiKey", "CLIENT_SECRET", "auth_token", "secretKey"])
        elif secret_type == "password":
            val = random_string(alphanumeric + "!@#$%^&*", random.randint(12, 28))
            ctx = random.choice(["password", "passwd", "db_password", "user_pass", "admin_secret"])
        else:  # jwt_token
            header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSJ9"
            signature = random_string(alphanumeric + "_-", 43)
            val = f"{header}.{payload}.{signature}"
            ctx = random.choice(["jwt_token", "auth_header", "bearer_token"])

        samples.append((val, ctx, is_quoted, 1))

    return samples


def generate_benign(count=1500) -> list[tuple[str, str, bool, int]]:
    """Generates synthetic benign, non-secret examples (label=0)."""
    samples = []
    hex_chars = string.hexdigits[:16].lower()
    alphanumeric = string.ascii_letters + string.digits

    placeholders = [
        "YOUR_API_KEY_HERE", "your_secret_token_here", "insert_password_here",
        "TODO_REPLACE_WITH_REAL_KEY", "CHANGEME", "xxxxxxxx-xxxx-xxxx",
        "example_api_key_12345", "REPLACE_ME", "DUMMY_KEY_FOR_TESTING",
        "not_a_real_secret", "sample_token_abc"
    ]

    words = [
        "userProfile", "defaultTimeout", "connectionTimeout", "retryAttempts",
        "databaseHost", "applicationName", "componentId", "backgroundColor",
        "marginLeft", "borderStyle", "requestHandler", "dispatchAction"
    ]

    configs = [
        "application/json", "text/html; charset=utf-8", "http://localhost:8080",
        "https://api.github.com/v3", "postgresql://localhost:5432/testdb",
        "2026-11-09T20:30:00Z", "v2.14.0", "SELECT * FROM users WHERE active = 1"
    ]

    for _ in range(count):
        benign_type = random.choice([
            "uuid", "git_hash", "checksum", "placeholder",
            "identifier", "config_value", "random_hex"
        ])
        is_quoted = random.choice([True, False])

        if benign_type == "uuid":
            val = str(uuid.uuid4())
            ctx = random.choice(["id", "userId", "requestId", "trace_id", "session_id"])
        elif benign_type == "git_hash":
            val = random_string(hex_chars, 40)
            ctx = random.choice(["commit_hash", "git_sha", "revision", "head_commit"])
        elif benign_type == "checksum":
            val = random_string(hex_chars, 64)
            ctx = random.choice(["sha256", "checksum", "file_hash", "md5"])
        elif benign_type == "placeholder":
            val = random.choice(placeholders)
            ctx = random.choice(["api_key", "password", "token", "secret"])
        elif benign_type == "identifier":
            val = random.choice(words)
            ctx = random.choice(["name", "prop", "style", "config", "type"])
        elif benign_type == "config_value":
            val = random.choice(configs)
            ctx = random.choice(["content_type", "api_base_url", "timestamp", "query"])
        else:  # random_hex
            val = random_string(hex_chars, random.randint(8, 20))
            ctx = random.choice(["color", "hex_id", "tag", "counter"])

        samples.append((val, ctx, is_quoted, 0))

    return samples


def generate_and_save_dataset():
    """Generates dataset and writes features + labels to CSV."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    secrets = generate_secrets(count=1500)
    benign = generate_benign(count=1500)
    all_samples = secrets + benign
    random.shuffle(all_samples)

    header = FEATURE_NAMES + ["label"]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for val, ctx, is_quoted, label in all_samples:
            feats = extract_features(val, ctx, is_quoted)
            writer.writerow(feats + [label])

    print(f"Generated {len(all_samples)} samples (1500 secrets, 1500 benign) -> {OUTPUT_CSV}")


if __name__ == "__main__":
    generate_and_save_dataset()

