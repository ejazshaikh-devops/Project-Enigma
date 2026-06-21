"""
GuardAI ML — URL Feature Extraction

Extracts a fixed-length numeric feature vector from a URL for the
lightweight phishing classifier. All features are computed from the URL
string alone — no network calls, no page content — so this is fast
(<1ms) and works even if the threat-intel providers are down.

This module is imported by both the training script (ml/train_model.py)
and the live inference path (ml/predict.py), so the feature definitions
can never drift between training and serving.
"""

import math
import re
from urllib.parse import urlparse

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_subdomains",
    "num_query_params",
    "num_special_chars",
    "digit_ratio",
    "has_https",
    "has_ip_host",
    "has_at_symbol",
    "has_suspicious_tld",
    "has_port",
    "path_entropy",
    "hostname_entropy",
    "num_phishing_keywords",
    "has_double_slash_in_path",
    "longest_word_length",
    "vowel_consonant_ratio",
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
    "loan", "work", "date", "faith", "racing", "cricket",
    "science", "party", "review", "country", "stream", "download",
    "accountant", "win", "men", "gdn", "bid",
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "confirm", "password", "credential", "support", "suspended", "urgent",
    "alert", "recover", "validate", "reactivate", "wallet", "claim",
]


def _shannon_entropy(s: str) -> float:
    """Higher entropy = more random-looking string (common in generated phishing domains)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_features(raw_url: str) -> list[float]:
    """
    Returns a fixed-length list of floats, in the same order as FEATURE_NAMES.
    Designed to never raise — malformed URLs get a "maximally suspicious"
    feature vector rather than crashing the request.
    """
    try:
        parsed = urlparse(raw_url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        return [1.0] * len(FEATURE_NAMES)

    if not hostname:
        return [1.0] * len(FEATURE_NAMES)

    full = raw_url.lower()

    url_length = len(raw_url)
    hostname_length = len(hostname)
    path_length = len(path)
    num_dots = hostname.count(".")
    num_hyphens = hostname.count("-")
    num_digits = sum(c.isdigit() for c in hostname)
    num_subdomains = max(0, num_dots - 1)
    num_query_params = len(query.split("&")) if query else 0
    num_special_chars = sum(1 for c in full if c in "!@#$%^&*()_+={}[]|\\:;\"'<>,?")
    digit_ratio = num_digits / max(len(hostname), 1)

    has_https = 1.0 if parsed.scheme == "https" else 0.0
    has_ip_host = 1.0 if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", hostname) else 0.0
    has_at_symbol = 1.0 if "@" in full.split("//", 1)[-1] else 0.0

    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    has_suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    has_port = 1.0 if parsed.port else 0.0

    path_entropy = _shannon_entropy(path)
    hostname_entropy = _shannon_entropy(hostname.replace(".", ""))

    num_phishing_keywords = sum(1 for kw in PHISHING_KEYWORDS if kw in full)
    has_double_slash_in_path = 1.0 if "//" in path else 0.0

    words = re.split(r"[./\-_?=&]", hostname + path)
    words = [w for w in words if w]
    longest_word_length = max((len(w) for w in words), default=0)

    vowels = sum(1 for c in hostname if c in "aeiou")
    consonants = sum(1 for c in hostname if c.isalpha() and c not in "aeiou")
    vowel_consonant_ratio = vowels / max(consonants, 1)

    return [
        float(url_length),
        float(hostname_length),
        float(path_length),
        float(num_dots),
        float(num_hyphens),
        float(num_digits),
        float(num_subdomains),
        float(num_query_params),
        float(num_special_chars),
        float(digit_ratio),
        has_https,
        has_ip_host,
        has_at_symbol,
        has_suspicious_tld,
        has_port,
        float(path_entropy),
        float(hostname_entropy),
        float(num_phishing_keywords),
        has_double_slash_in_path,
        float(longest_word_length),
        float(vowel_consonant_ratio),
    ]
