# CloudGuard Machine Learning Component

## Overview

CloudGuard integrates a dedicated **Random Forest Classifier** (`scikit-learn`) to evaluate candidate strings discovered during code scanning. The model analyzes 14 engineered numeric features derived from candidate characters, Shannon entropy, prefix markers, and contextual variable names to estimate whether a string is likely to be an exposed secret (`label 1`) or a benign identifier / test fixture / hash (`label 0`).

## Feature Engineering

The model takes 14 features for each candidate:

| Feature | Type | Description |
|---|---|---|
| `length` | Float | Number of characters in candidate |
| `entropy` | Float | Shannon entropy $H = -\sum p_i \log_2(p_i)$ |
| `uppercase_ratio` | Float | Proportion of uppercase characters |
| `lowercase_ratio` | Float | Proportion of lowercase characters |
| `digit_ratio` | Float | Proportion of numeric digits |
| `special_ratio` | Float | Proportion of non-alphanumeric characters |
| `unique_char_ratio` | Float | Number of unique characters divided by length |
| `has_uppercase` | Binary (0/1) | Whether uppercase characters are present |
| `has_lowercase` | Binary (0/1) | Whether lowercase characters are present |
| `has_digits` | Binary (0/1) | Whether numeric digits are present |
| `has_special_chars` | Binary (0/1) | Whether special characters are present |
| `has_known_prefix` | Binary (0/1) | Matches known token prefixes (`AKIA`, `ghp_`, `sk_live_`, `xoxb-`, etc.) |
| `context_keyword_score` | Float | Weighted score based on nearby variable names (`secret`, `password`, `api_key`, etc.) |
| `is_quoted_value` | Binary (0/1) | Whether extracted from a quoted assignment |

## Reproducible Pipeline

1. **Dataset Generation:**
   ```bash
   cd ml
   python generate_dataset.py
   ```
   Generates 3,000 synthetic balanced samples (1,500 secrets, 1,500 benign) with a fixed random seed (`42`). Does **not** use real production credentials.

2. **Model Training & Evaluation:**
   ```bash
   python train_model.py
   ```
   Splits dataset 80/20 stratified, trains `RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)`, evaluates precision, recall, F1, confusion matrix, and feature importances, and saves:
   - Serialized model: `ml/models/secret_classifier.joblib`
   - Evaluation metrics: `ml/evaluation/metrics.json`

3. **Inference Integration:**
   Imported by `backend/app/services/detection_service.py` via `ml/predictor.py`.

