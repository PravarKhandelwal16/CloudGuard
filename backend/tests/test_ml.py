import pytest
from ml.features import extract_features, calculate_entropy, calculate_context_keyword_score, FEATURE_NAMES
from ml.predictor import predict_candidate, load_model, MLPredictorError


def test_feature_extractor_types_and_length():
    # Empty string
    feats_empty = extract_features("")
    assert len(feats_empty) == len(FEATURE_NAMES)
    assert all(f == 0.0 for f in feats_empty)

    # Candidate with known prefix and context
    feats = extract_features("AKIAIOSFODNN7EXAMPLE", context="AWS_ACCESS_KEY_ID", is_quoted=True)
    assert len(feats) == len(FEATURE_NAMES)
    assert feats[0] == 20.0  # length
    assert feats[1] > 3.0   # entropy
    assert feats[11] == 1.0 # has_known_prefix
    assert feats[12] > 0.0  # context_keyword_score
    assert feats[13] == 1.0 # is_quoted_value


def test_predictor_inference():
    # Synthetic AWS Key
    res_secret = predict_candidate("AKIAIOSFODNN7EXAMPLE", context="AWS_ACCESS_KEY_ID", is_quoted=True)
    assert res_secret["ml_available"] is True
    assert res_secret["is_secret"] is True
    assert 0.0 <= res_secret["confidence"] <= 1.0

    # Benign variable / placeholder
    res_benign = predict_candidate("insert_password_here", context="config", is_quoted=False)
    assert res_benign["is_secret"] is False


def test_missing_model_error():
    with pytest.raises(MLPredictorError):
        load_model("non_existent_model_file.joblib")

