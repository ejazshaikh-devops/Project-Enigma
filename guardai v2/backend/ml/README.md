# GuardAI ML — Phishing Classifiers

GuardAI ships with **two independent ML signals**, both optional and
fail-safe (the system works fine with neither, one, or both loaded):

1. **Pre-trained model** (`pretrained_predict.py`) — a real, open-source
   model downloaded from Hugging Face, trained on real labeled phishing
   data. **Use this one if you want genuine "trained on real data" AI
   with zero training effort on your end.**
2. **Synthetic model** (`predict.py`) — built in-house, trained on
   programmatically generated data (see below), since this project had
   no labeled dataset of its own. Always available as a fallback.

When both are loaded, `routers/analyze.py` takes the stronger signal from
either (max of the two probabilities) and prefers the pre-trained model's
score for the `ai_score` field shown to users, since it's trained on real
outcomes rather than synthetic patterns.

---

## Option 1: Pre-trained model (recommended)

**Source:** [`pirocheto/phishing-url-detection`](https://huggingface.co/pirocheto/phishing-url-detection)
on Hugging Face — MIT licensed, trained on a real public dataset of
11,400+ labeled phishing/legitimate URLs.

**Published metrics** (from the model card, not our own claim):

| Metric | Value |
|--------|-------|
| ROC-AUC | 0.987 |
| Accuracy | 0.949 |
| F1 | 0.949 |
| Precision | 0.948 |
| Recall | 0.950 |

**Model type:** Linear SVM, distributed as ONNX (not pickle — avoids the
arbitrary-code-execution risk that comes with loading untrusted `.pkl`
files). It takes a raw URL string as input and does its own internal
feature extraction — you don't need to engineer features for it.

### Setup (one-time, requires internet access)

```bash
cd backend
pip install -r ml/requirements-download.txt --break-system-packages
python3 -m ml.download_pretrained_model
```

This downloads `model.onnx` (a few hundred KB) to `ml/pretrained/model.onnx`.
Restart the backend and it's automatically picked up — check
`GET /v1/health` and look for `ml_pretrained_model.loaded: true`.

**Important — this could not be verified from within this build
environment**: the sandbox this code was developed in has a restricted
network allowlist that does not include `huggingface.co`, so the download
and live inference against the real `.onnx` file could not be tested
end-to-end here. The integration logic itself (`routers/analyze.py`
calling `predict_pretrained_probability()`, blending the result, fail-safe
behavior when absent) **was** tested — including a mocked test confirming
the blending logic correctly elevates the verdict when the model returns
a high probability. **Before relying on this in production, run it
yourself on a machine with internet access and confirm the actual
predictions look sane on a few known URLs** — see the verification
snippet below.

```bash
# Quick sanity check after downloading:
python3 -c "
from ml.pretrained_predict import predict_pretrained_probability
print('known phishing pattern:', predict_pretrained_probability('http://paypal-verify-secure.tk/login'))
print('known legit site:', predict_pretrained_probability('https://www.wikipedia.org/'))
"
```

If you don't have internet access on your EC2 instance at deploy time
(or prefer not to add the `onnxruntime` dependency), simply skip this —
the synthetic model below still runs and the product works fully without
the pre-trained model.

---

## Option 2: Synthetic model (built-in, always available)

A logistic regression model trained on 21 lexical/structural features
extracted from a URL string (length, hyphen count, TLD risk, entropy,
phishing-keyword presence, etc).

**This is intentionally not a deep learning / transformer-based model.**
Given the constraints — no database, no labeled production data yet,
needs to run on a 1-2GB RAM EC2 instance with sub-millisecond latency
per request — a small linear model trained on hand-engineered features
is the right tool. It's fast, inspectable (we can say *why* it flagged
something, which a black-box neural net makes much harder), and has zero
GPU/heavy-runtime requirements.

## How it's trained

You don't have real labeled production data yet (by design — no
database, no stored browsing history). `ml/training_data/generate_dataset.py`
generates a synthetic-but-grounded dataset:

- **Phishing examples** follow real attacker patterns: typosquatting
  (homoglyphs, character swaps/omissions/insertions), brand names stuffed
  into subdomains, IP-address hosts, suspicious TLDs, keyword stuffing.
  ~20% are "hard negatives" — HTTPS, clean TLD, just a convincing typosquat
  — so the model can't rely on shortcuts like "HTTP = phishing."
- **Legitimate examples** are built from ~50 real high-traffic domains
  with realistic paths, including query strings, campaign subdomains, and
  — critically — **real login/auth pages** (`accounts.google.com/signin`,
  `login.microsoftonline.com/...`, etc). This class exists specifically
  because early testing caught the model flagging legitimate Google/Apple/
  Microsoft sign-in pages as "dangerous" simply because the path contained
  the word "signin" or "login" — a real false-positive bug found and fixed
  during this build, not a hypothetical concern.

This is a standard bootstrapping technique (sometimes called weak
supervision) for a v1 model when no hand-labeled corpus exists yet. It
produces a model that's measurably useful — see test results below — but
it is **not a substitute for real labeled outcomes once you have them.**

## Honest limitations

- The model has never seen a real attacker's actual phishing kit — only
  patterns it was told are "what phishing looks like." Sophisticated,
  novel phishing campaigns that don't match these patterns may slip
  through the ML signal (though the rules engine and live threat-intel
  feeds provide independent backstops).
- Synthetic data can encode the generator's own biases. We mitigated the
  most serious one found during testing (login-keyword false positives)
  but others may exist. Treat ML-driven verdicts as one signal among
  three, not gospel — this is exactly why `routers/analyze.py` never lets
  the ML score alone determine "dangerous" without contributing context
  in `reasons`.
- 21 features is a deliberately small, fast set. It will not catch
  phishing techniques that don't show up in the URL itself (e.g a
  phishing page hosted on a legitimately compromised, previously-trusted
  domain) — that's what the page-content signals in
  `extension/content/detector.js` and brand-impersonation in
  `core/domain_analysis.py` are for; they're independent layers.
- **`url_length` and `path_length` have near-total distributional
  overlap between phishing and legitimate URLs in this training set**
  (verified: legit p10-p90 range 25-69 chars, phishing 27-59 chars —
  almost the same). A second real bug was found and fixed during testing
  because of this: short, low-feature-count legitimate URLs
  (`https://google.com/`, `https://amazon.com/`) scored as high as 76%
  "phishing" purely from being unusually short, with zero other risk
  signal present. This wasn't visible in train/test accuracy (which
  looked fine, 97-98%) — it only surfaced when testing specific
  real-world domains by hand, which is why `train_model.py` now runs an
  explicit real-world sanity check (known legitimate + known phishing
  domains, not from the synthetic generator) after every training run
  and prints a loud warning if any fail. The structural fix applied:
  `routers/analyze.py` now requires at least one corroborating signal
  (a triggered rule, a brand-impersonation hit, or the pre-trained model
  agreeing) before trusting the synthetic model's score at full strength
  — with zero corroboration, its contribution is capped below the
  "suspicious" threshold. This means the synthetic model can still
  independently flag URLs with real red flags, but can no longer
  single-handedly torch a clean, ordinary-looking domain on statistical
  noise alone. **If you retrain this model, re-run it and check the
  sanity-check output before deploying — don't trust accuracy/ROC-AUC
  numbers alone.**

## Files

| File | Purpose |
|------|---------|
| `pretrained_predict.py` | Inference wrapper for the downloaded pre-trained ONNX model |
| `download_pretrained_model.py` | One-time script to fetch the pre-trained model from Hugging Face |
| `requirements-download.txt` | Extra dependency (`huggingface_hub`) needed only to run the download script |
| `features.py` | Feature extraction for the synthetic model — shared between training and serving so they can never drift apart |
| `training_data/generate_dataset.py` | Synthetic dataset generator |
| `train_model.py` | Trains the synthetic logistic regression model, evaluates, exports `model.json` |
| `model.json` | Synthetic model's trained weights (plain JSON, no pickle) |
| `predict.py` | Live inference for the synthetic model — numpy only, no sklearn dependency at runtime |

## Retraining

```bash
cd backend
python3 -m ml.train_model
```

This regenerates the synthetic dataset (seeded, so it's reproducible),
retrains, evaluates on a held-out test split, prints feature importances,
and overwrites `ml/model.json`. The running backend picks up the new
model on next restart (it's loaded once at process start, cached in
memory).

## The real next step: train on actual outcomes

Once you have production traffic, the highest-value upgrade isn't a
fancier model architecture — it's replacing the synthetic labels with
real ones:

1. Log (without storing full URLs long-term, to stay privacy-compliant)
   which URLs your threat-intel providers confirmed as phishing vs. which
   were flagged "safe" and never triggered a user report.
2. Periodically retrain `train_model.py` against this real distribution
   instead of (or blended with) the synthetic generator.
3. The feature extraction, model format, and serving code don't need to
   change at all — only the training data source changes.

## Verified behavior (from this build's testing)

Held-out sanity check, URLs not seen during training:
- 10/10 legitimate sites (GitHub, Wikipedia, Amazon, Netflix, Gmail, etc.)
  correctly scored "safe"
- 8/8 phishing-pattern URLs (typosquats, IP hosts, suspicious TLDs,
  keyword-stuffed domains) correctly scored "dangerous"
- The specific false positive found during development — real login pages
  on Google/Microsoft/Apple/Bank of America flagged as dangerous purely
  for containing "login"/"signin" — is fixed and covered by the training
  set going forward.

This is not a claim of production-grade accuracy at scale — it's a
demonstration that the model learns real, sensible signal rather than
spurious correlations, and that the testing process caught and fixed a
real bug rather than just reporting a clean-looking accuracy number.
