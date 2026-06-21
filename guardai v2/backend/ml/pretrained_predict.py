"""
GuardAI ML — Pre-Trained Model Inference (pirocheto/phishing-url-detection)

Wraps the real, pre-trained ONNX model downloaded via
ml/download_pretrained_model.py. This model takes a raw URL string
directly (it does its own internal feature extraction/vectorization —
unlike ml/predict.py's synthetic model, which uses our hand-engineered
features in ml/features.py).

Design choice: this is kept as a SEPARATE, OPTIONAL signal rather than
replacing the synthetic model outright, for two reasons:
  1. Fail-safe: if you haven't run the download script yet (or the
     instance has no internet access at deploy time), the system must
     keep working on the synthetic model + rules + threat intel alone.
  2. Two independently-trained models agreeing is a stronger signal than
     either alone — routers/analyze.py takes the max of both when both
     are available, same pattern as the existing rules/ML/threat-intel
     blend.
"""

import logging
from pathlib import Path

logger = logging.getLogger("guardai.ml.pretrained")

_MODEL_PATH = Path(__file__).resolve().parent / "pretrained" / "model.onnx"

_session = None
_load_attempted = False


def _load_session():
    global _session, _load_attempted
    if _load_attempted:
        return _session
    _load_attempted = True

    if not _MODEL_PATH.exists():
        logger.info(
            "Pre-trained ONNX model not found at %s — skipping. "
            "Run `python3 -m ml.download_pretrained_model` to enable it "
            "(optional; the synthetic model + rules + threat intel still work without it).",
            _MODEL_PATH,
        )
        return None

    try:
        import onnxruntime
        _session = onnxruntime.InferenceSession(
            str(_MODEL_PATH), providers=["CPUExecutionProvider"]
        )
        logger.info("Pre-trained phishing-detection ONNX model loaded successfully.")
        return _session
    except ImportError:
        logger.warning(
            "onnxruntime is not installed — pre-trained model unavailable. "
            "Add `onnxruntime` to requirements.txt and reinstall to enable it."
        )
        return None
    except Exception as exc:
        logger.error("Failed to load pre-trained ONNX model: %s", exc)
        return None


def predict_pretrained_probability(url: str) -> float | None:
    """
    Returns phishing probability in [0, 1] from the pre-trained model, or
    None if it's not available. Never raises — a model loading/inference
    failure must never break a live request.
    """
    session = _load_session()
    if session is None:
        return None

    try:
        import numpy as np
        inputs = np.array([url], dtype="str")
        results = session.run(None, {"inputs": inputs})[1]
        # results[0] = [P(legitimate), P(phishing)] for this model's training labels
        return round(float(results[0][1]), 4)
    except Exception as exc:
        logger.error("Pre-trained model inference failed: %s", exc)
        return None


def pretrained_model_info() -> dict:
    session = _load_session()
    return {
        "loaded": session is not None,
        "source": "pirocheto/phishing-url-detection (Hugging Face, MIT license)",
        "model_type": "LinearSVM (ONNX)",
        "published_metrics": {
            "roc_auc": 0.9868,
            "accuracy": 0.9486,
            "f1": 0.9486,
        } if session is not None else None,
    }
