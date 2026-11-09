import pytest
from backend.app.scanner.rules import match_rules_in_line
from backend.app.scanner.entropy import calculate_entropy
from backend.app.scanner.candidate_extractor import extract_candidates_from_line
from backend.app.utils.masking import mask_secret


def test_masking_never_reveals_raw_secret():
    # Test short secret
    m_short = mask_secret("abc")
    assert m_short == "********"

    # Test medium secret
    m_med = mask_secret("abcdefgh")
    assert "abcdefgh" not in m_med
    assert m_med == "a****h"

    # Test AWS-like 20-char key ID
    m_aws = mask_secret("AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in m_aws
    assert m_aws.startswith("AKIA")
    assert m_aws.endswith("MPLE")
    assert "****" in m_aws

    # Test 40-char secret
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    m_sec = mask_secret(secret)
    assert secret not in m_sec
    assert "****" in m_sec

    # Test PEM Private Key
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...==\n-----END RSA PRIVATE KEY-----"
    m_pem = mask_secret(pem)
    assert "[MASKED KEY MATERIAL]" in m_pem
    assert "MIIEowIBAAKCAQEA0" not in m_pem


def test_entropy_calculation():
    # Low entropy: repeating chars
    assert calculate_entropy("aaaaaaaaaa") == 0.0
    # Moderate entropy: simple word
    assert calculate_entropy("hello world") < 3.2
    # High entropy: random alphanumeric token
    high_ent = calculate_entropy("wJalrXUtnFEMIK7MDENGbPxRfiCY123456789")
    assert high_ent > 4.0


def test_rule_aws_access_key_id():
    line = 'const aws_key_id = "AKIA1234567890ABCDEF";'
    matches = match_rules_in_line(line)
    assert any(m["rule_id"] == "aws_access_key_id" for m in matches)
    match = next(m for m in matches if m["rule_id"] == "aws_access_key_id")
    assert match["severity"] == "High"
    assert match["candidate"] == "AKIA1234567890ABCDEF"


def test_rule_aws_secret_key():
    line = 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    matches = match_rules_in_line(line)
    assert any(m["rule_id"] == "aws_secret_key" for m in matches)
    match = next(m for m in matches if m["rule_id"] == "aws_secret_key")
    assert match["severity"] == "Critical"


def test_rule_github_token():
    line = 'export GITHUB_TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"'
    matches = match_rules_in_line(line)
    assert any(m["rule_id"] == "github_token" for m in matches)
    match = next(m for m in matches if m["rule_id"] == "github_token")
    assert match["severity"] == "Critical"


def test_rule_db_connection_uri():
    line = 'DATABASE_URL="postgresql://postgres:SuperSecretP@ss123@db.example.com:5432/mydb"'
    matches = match_rules_in_line(line)
    assert any(m["rule_id"] == "db_connection_uri" for m in matches)
    match = next(m for m in matches if m["rule_id"] == "db_connection_uri")
    assert match["severity"] == "Critical"
    assert match["candidate"] == "SuperSecretP@ss123"


def test_rule_private_key():
    line = "-----BEGIN RSA PRIVATE KEY-----"
    matches = match_rules_in_line(line)
    assert any(m["rule_id"] == "private_key" for m in matches)
    match = next(m for m in matches if m["rule_id"] == "private_key")
    assert match["severity"] == "Critical"


def test_rule_generic_password():
    line = 'db_password = "MyComplexPassword123!"'
    matches = match_rules_in_line(line)
    assert any(m["rule_id"] == "generic_password" for m in matches)


def test_candidate_extraction():
    line = 'var apiKey = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d";'
    rules = match_rules_in_line(line)
    candidates = extract_candidates_from_line(line, 42, rules)
    assert len(candidates) >= 1
    assert any("9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d" in c.value for c in candidates)

