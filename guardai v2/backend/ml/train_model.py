"""
GuardAI ML — Model Training

Trains a logistic regression classifier on lexical/structural URL features.

Why logistic regression and not a deep model:
  - Training set is synthetic/weak-labeled (see training_data/generate_dataset.py)
    — a complex model would overfit to the synthetic generator's quirks
    rather than learning generalizable phishing signal.
  - Inference must be fast (<5ms) and dependency-light enough to run on a
    1-2GB RAM EC2 instance alongside the rest of the app — no GPU, no
    heavy runtime.
  - Logistic regression coefficients are inspectable, which matters for
    an "explainable AI verdict" product — we can report which features
    pushed the score up, not just a black-box number.

Run with: python3 -m ml.train_model   (from the backend/ directory)
Outputs: ml/model.json  (weights + bias + feature names + scaler stats)
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.features import extract_features, FEATURE_NAMES
from ml.training_data.generate_dataset import generate_dataset


def main():
    print("Generating training data...")
    urls, labels = generate_dataset(n_per_class=3000)

    print("Extracting features...")
    X = np.array([extract_features(u) for u in urls])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Standardize features (mean 0, std 1) — store stats for inference-time scaling
    mean = X_train.mean(axis=0)
    std = X_train.std(axis=0)
    std[std == 0] = 1.0  # avoid div-by-zero for constant features

    X_train_scaled = (X_train - mean) / std
    X_test_scaled = (X_test - mean) / std

    print("Training logistic regression...")
    # C=0.3 (stronger L2 regularization than the default C=1.0) — found
    # necessary during testing: with weaker regularization, the model
    # assigned large weight to url_length and path_length, which have
    # near-total distributional overlap between the two classes (see
    # ml/README.md) but happened to sit at opposite statistical extremes
    # for a few real domains (google.com, amazon.com — unusually SHORT
    # legitimate URLs) and for synthetic-edge-case phishing URLs. This
    # caused real false positives: google.com scored 63-76% "phishing" in
    # earlier versions of this model purely from URL length, with no other
    # risk signal present. Stronger regularization shrinks weight on noisy/
    # overlapping features and relies more on genuinely separating ones
    # (suspicious TLD, HTTPS absence, phishing keywords).
    model = LogisticRegression(max_iter=1000, C=0.3, class_weight="balanced")
    model.fit(X_train_scaled, y_train)

    print("\n── Evaluation on held-out test set ──")
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

    print("\n── 5-fold cross-validation (catches single-split luck) ──")
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring="roc_auc")
    print(f"CV ROC-AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    print("\n── Real-world sanity check (known domains, NOT from the synthetic generator) ──")
    print("This check exists because synthetic train/test accuracy can look perfect")
    print("while the model still fails on real URLs outside the generator's exact")
    print("patterns — this caught a real bug (google.com scoring 76% phishing)")
    print("during development. A failure here is a stronger signal than the metrics above.")

    known_legitimate = [
        "https://google.com/", "https://www.google.com/", "https://amazon.com/",
        "https://github.com/", "https://wikipedia.org/", "https://netflix.com/",
        "https://stripe.com/", "https://apple.com/", "https://microsoft.com/",
        "https://accounts.google.com/signin", "https://login.microsoftonline.com/",
    ]
    known_phishing = [
        "http://paypa1-secure-login.tk/verify", "http://192.168.1.1/bank/login.php",
        "https://app1e-id-verify.xyz/signin", "http://amaz0n-billing-update.gq/account",
    ]

    def _score(url):
        raw = np.array(extract_features(url))
        scaled = (raw - mean) / std
        z = float(np.dot(scaled, model.coef_[0]) + model.intercept_[0])
        return 1.0 / (1.0 + np.exp(-z))

    sanity_failures = []
    for url in known_legitimate:
        p = _score(url)
        status = "OK" if p < 0.5 else "FAIL (false positive)"
        if p >= 0.5:
            sanity_failures.append((url, p, "expected legitimate"))
        print(f"  [{status:22s}] {url:48s} p(phishing)={p:.3f}")
    for url in known_phishing:
        p = _score(url)
        status = "OK" if p >= 0.5 else "FAIL (false negative)"
        if p < 0.5:
            sanity_failures.append((url, p, "expected phishing"))
        print(f"  [{status:22s}] {url:48s} p(phishing)={p:.3f}")

    if sanity_failures:
        print(f"\n  WARNING: {len(sanity_failures)} real-world sanity check(s) failed.")
        print("  Do not deploy this model.json until these are resolved — adjust")
        print("  training_data/generate_dataset.py to better cover the failing")
        print("  pattern, or increase regularization (lower C), then retrain.")
    else:
        print("\n  All real-world sanity checks passed.")

    print("\n── Feature importance (standardized coefficients) ──")
    coefs = model.coef_[0]
    importance = sorted(zip(FEATURE_NAMES, coefs), key=lambda x: -abs(x[1]))
    for name, coef in importance:
        direction = "→ phishing" if coef > 0 else "→ legitimate"
        print(f"  {name:28s} {coef:+.3f}  {direction}")

    # Export as plain JSON — no pickle, no sklearn dependency needed at
    # inference time. This keeps the runtime container lightweight and
    # avoids sklearn version-skew issues between training and serving.
    model_export = {
        "version": "1.0.0",
        "feature_names": FEATURE_NAMES,
        "scaler_mean": mean.tolist(),
        "scaler_std": std.tolist(),
        "coefficients": coefs.tolist(),
        "intercept": float(model.intercept_[0]),
        "trained_on": "synthetic_weak_supervision_v1",
        "test_roc_auc": float(roc_auc_score(y_test, y_proba)),
    }

    out_path = Path(__file__).resolve().parent / "model.json"
    with open(out_path, "w") as f:
        json.dump(model_export, f, indent=2)

    print(f"\nModel exported to {out_path}")


if __name__ == "__main__":
    main()
