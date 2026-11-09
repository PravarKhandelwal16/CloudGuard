import os
import joblib
import numpy as np
from pathlib import Path
import sys

# Ensure ml directory is on path if needed
ml_dir = Path(__file__).resolve().parent
if str(ml_dir) not in sys.path:
    sys.path.insert(0, str(ml_dir))

from features import extract_features, FEATURE_NAMES

_MODEL_INSTANCE = None
_MODEL_VERSION = "rf-v1.0.0"
_MODEL_PATH = ml_dir / "models" / "secret_classifier.joblib"


class MLPredictorError(Exception):
    """Raised when the ML model cannot be loaded or inference fails."""
    pass


def load_model(custom_path: str = None):
    """Loads the serialized Random Forest model and metadata."""
    global _MODEL_INSTANCE, _MODEL_VERSION

    path = Path(custom_path) if custom_path else _MODEL_PATH
    if not path.exists():
        raise MLPredictorError(f"ML model file not found at {path}. Run ml/train_model.py first.")

    try:
        data = joblib.load(path)
        if isinstance(data, dict) and "model" in data:
            _MODEL_INSTANCE = data["model"]
            _MODEL_VERSION = data.get("version", "rf-v1.0.0")
        else:
            _MODEL_INSTANCE = data
            _MODEL_VERSION = "rf-v1.0.0"
        return _MODEL_INSTANCE
    except Exception as e:
        raise MLPredictorError(f"Failed to load ML model from {path}: {str(e)}") from e


def get_predictor(custom_path: str = None):
    global _MODEL_INSTANCE
    if _MODEL_INSTANCE is None:
        load_model(custom_path)
    return _MODEL_INSTANCE


def predict_candidate(candidate: str, context: str = "", is_quoted: bool = False, threshold: float = 0.50) -> dict:
    """
    Evaluates candidate string using Random Forest feature extraction and inference.
    Returns prediction dictionary without returning raw candidate.
    """
    import pandas as pd
    model = get_predictor()
    features = extract_features(candidate, context, is_quoted)
    features_df = pd.DataFrame([features], columns=FEATURE_NAMES)

    prob = float(model.predict_proba(features_df)[0][1])
    is_secret = bool(prob >= threshold)

    return {
        "is_secret": is_secret,
        "confidence": round(prob if is_secret else (1.0 - prob), 4),
        "probability": round(prob, 4),
        "version": _MODEL_VERSION,
        "ml_available": True
    }
