"""
GuardAI ML — Live Inference

Loads the trained logistic regression model (plain JSON — no pickle, no
sklearn needed at runtime) and scores a URL in well under a millisecond.

Why this is safe to run on a small EC2 instance:
  - model.json is ~3-5KB, loaded once at process startup
  - Inference is a single dot product (numpy), no model framework overhead
  - No GPU, no torch/tensorflow, the only added dependency is numpy
    (a few MB), which is dramatically lighter than shipping a real
    sklearn/torch inference stack into a 1-2GB RAM container
"""

import json
import logging
import math
from pathlib import Path

import numpy as np

from ml.features import extract_features, FEATURE_NAMES

logger = logging.getLogger("guardai.ml.predict")

_MODEL_PATH = Path(__file__).resolve().parent / "model.json"

_model = None


def _load_model():
    global _model
    if _model is not None:
        return _model
    try:
        with open(_MODEL_PATH) as f:
            _model = json.load(f)
        if _model.get("feature_names") != FEATURE_NAMES:
            logger.error(
                "ml/model.json was trained with a different feature set than "
                "ml/features.py currently defines — retrain the model "
                "(python3 -m ml.train_model) before trusting its output."
            )
            _model = None
        return _model
    except FileNotFoundError:
        logger.warning("ml/model.json not found — AI scoring disabled, falling back to rules-only verdicts. Run `python3 -m ml.train_model` to generate it.")
        return None
    except Exception as exc:
        logger.error("Failed to load ml/model.json: %s", exc)
        return None


def _sigmoid(z: float) -> float:
    # Numerically stable sigmoid
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


def predict_phishing_probability(url: str) -> float | None:
    """
    Returns a probability in [0, 1] that the URL is phishing, or None if
    the model isn't available (caller should fall back to rules-only
    scoring — this must never raise or block the request).
    """
    model = _load_model()
    if model is None:
        return None

    try:
        raw_features = np.array(extract_features(url))
        mean = np.array(model["scaler_mean"])
        std = np.array(model["scaler_std"])
        scaled = (raw_features - mean) / std

        coefs = np.array(model["coefficients"])
        intercept = model["intercept"]

        z = float(np.dot(scaled, coefs) + intercept)
        return round(_sigmoid(z), 4)
    except Exception as exc:
        logger.error("ML inference failed for a URL: %s", exc)
        return None


def explain_prediction(url: str, top_n: int = 3) -> list[str]:
    """
    Returns up to top_n human-readable reasons for the prediction, derived
    from which features contributed most to pushing the score toward
    phishing. This keeps the ML component consistent with the product's
    "explainable AI verdict" requirement — not a black box.
    """
    model = _load_model()
    if model is None:
        return []

    try:
        raw_features = np.array(extract_features(url))
        mean = np.array(model["scaler_mean"])
        std = np.array(model["scaler_std"])
        scaled = (raw_features - mean) / std
        coefs = np.array(model["coefficients"])

        # Per-feature contribution to the logit
        contributions = scaled * coefs
        ranked_idx = np.argsort(-contributions)  # most positive (most "phishing") first

        labels = {
            "num_phishing_keywords": "URL contains multiple phishing-related keywords",
            "has_suspicious_tld": "Domain uses a high-risk extension",
            "has_https": "Connection lacks HTTPS encryption",
            "num_digits": "Unusual number of digits in the domain",
            "digit_ratio": "High proportion of digits in the domain",
            "num_hyphens": "Excessive hyphens in the domain",
            "has_ip_host": "Uses a raw IP address instead of a domain name",
            "hostname_entropy": "Domain name looks randomly generated",
            "url_length": "Unusually long URL",
            "num_subdomains": "Unusual subdomain structure",
        }

        reasons = []
        for idx in ranked_idx[:top_n]:
            contribution = contributions[idx]
            if contribution <= 0.15:  # not meaningfully pushing toward phishing
                continue
            name = FEATURE_NAMES[idx]
            if name in labels:
                reasons.append(f"AI model: {labels[name]}")
        return reasons
    except Exception:
        return []


def model_info() -> dict:
    model = _load_model()
    if model is None:
        return {"loaded": False}
    return {
        "loaded": True,
        "version": model.get("version"),
        "trained_on": model.get("trained_on"),
        "test_roc_auc": model.get("test_roc_auc"),
    }
