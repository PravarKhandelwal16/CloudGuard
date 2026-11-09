import os
import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    precision_score, recall_score, f1_score, accuracy_score,
    confusion_matrix, classification_report
)
from features import FEATURE_NAMES

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "synthetic_secrets_dataset.csv"
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "secret_classifier.joblib"
EVAL_DIR = BASE_DIR / "evaluation"
METRICS_PATH = EVAL_DIR / "metrics.json"


def train_and_evaluate():
    print("Loading synthetic training dataset...")
    df = pd.read_csv(DATASET_PATH)

    X = df[FEATURE_NAMES]
    y = df["label"]

    print(f"Dataset shape: {X.shape}, class distribution: {dict(y.value_counts())}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}")

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )

    print("Training RandomForestClassifier...")
    clf.fit(X_train, y_train)

    # Predictions
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    precision = float(precision_score(y_test, y_pred))
    recall = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    accuracy = float(accuracy_score(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Calculate feature importances
    importances = {
        name: round(float(imp), 4)
        for name, imp in zip(FEATURE_NAMES, clf.feature_importances_)
    }
    # Sort by importance descending
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    metrics = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "test_size": 0.20,
        "threshold": 0.50,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": {
            "true_negatives": cm[0][0],
            "false_positives": cm[0][1],
            "false_negatives": cm[1][0],
            "true_positives": cm[1][1],
        },
        "feature_importances": sorted_importances,
        "version": "rf-v1.0.0"
    }

    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    # Save model and feature names dictionary
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model_payload = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "version": "rf-v1.0.0",
        "metrics": metrics
    }
    joblib.dump(model_payload, MODEL_PATH)

    print(f"\nModel saved successfully -> {MODEL_PATH}")
    print(f"Metrics saved -> {METRICS_PATH}")
    print("\nEvaluation Results:")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Confusion Matrix: {cm}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    return metrics


if __name__ == "__main__":
    train_and_evaluate()

