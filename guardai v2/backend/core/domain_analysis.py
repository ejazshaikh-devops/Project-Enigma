"""
GuardAI Backend — Brand Impersonation & Domain Analysis Engine

Server-side authoritative version of the heuristics that also run locally in
the extension. The backend re-derives these independently rather than
trusting the extension's local_score, since client-side JS can be tampered
with by a malicious page or modified extension build.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlparse

HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g",
    "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "!": "i",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ӏ": "l",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".loan", ".work", ".date", ".faith", ".racing", ".cricket",
    ".science", ".party", ".review", ".country", ".stream", ".download",
    ".accountant", ".win", ".men", ".gdn", ".bid",
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "banking",
    "confirm", "password", "credential", "support", "suspended", "urgent",
    "alert", "recover", "validate", "reactivate",
]

# name -> set of legitimate registered domains
PROTECTED_BRANDS: dict[str, set[str]] = {
    "paypal":        {"paypal.com"},
    "apple":         {"apple.com", "icloud.com"},
    "microsoft":     {"microsoft.com", "live.com", "outlook.com", "office.com"},
    "amazon":        {"amazon.com", "amazon.co.uk", "amazon.in"},
    "netflix":       {"netflix.com"},
    "google":        {"google.com", "gmail.com", "youtube.com"},
    "facebook":      {"facebook.com", "fb.com", "messenger.com"},
    "instagram":     {"instagram.com"},
    "twitter":       {"twitter.com", "x.com"},
    "linkedin":      {"linkedin.com"},
    "bankofamerica": {"bankofamerica.com"},
    "chase":         {"chase.com", "jpmorgan.com"},
    "wellsfargo":    {"wellsfargo.com"},
    "coinbase":      {"coinbase.com"},
    "binance":       {"binance.com"},
    "metamask":      {"metamask.io"},
    "opensea":       {"opensea.io"},
    "paytm":         {"paytm.com"},
    "hdfc":          {"hdfcbank.com"},
    "icici":         {"icicibank.com"},
    "sbi":           {"sbi.co.in", "onlinesbi.sbi"},
    "axis":          {"axisbank.com"},
}


@dataclass
class BrandHit:
    type: str
    brand: str
    confidence: int
    evidence: str


@dataclass
class DomainAnalysisResult:
    score: float
    triggered_rules: list[str] = field(default_factory=list)
    brand_hits: list[BrandHit] = field(default_factory=list)


def normalize_homoglyphs(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text.lower())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def detect_brand_impersonation(hostname: str) -> list[BrandHit]:
    hostname = hostname.lower().lstrip("www.")
    normalized = normalize_homoglyphs(hostname)
    parts = hostname.split(".")
    sld_full = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    sld_label = parts[-2] if len(parts) >= 2 else hostname
    subdomain = ".".join(parts[:-2])

    hits: list[BrandHit] = []

    for brand, legit_domains in PROTECTED_BRANDS.items():
        if hostname in legit_domains or sld_full in legit_domains:
            continue  # legitimate — skip

        # Subdomain spoofing: paypal.secure-login.xyz
        if brand in subdomain:
            hits.append(BrandHit(
                type="brand_subdomain_spoof",
                brand=brand,
                confidence=90,
                evidence=f'Brand "{brand}" appears in subdomain of an unrelated domain',
            ))
            continue

        # Typosquatting via edit distance: paypa1, gogle
        sld_norm = normalize_homoglyphs(sld_label)
        dist = levenshtein(sld_norm, brand)
        if 0 < dist <= 2 and len(sld_norm) >= 4:
            hits.append(BrandHit(
                type="typosquatting",
                brand=brand,
                confidence=round((1 - dist / max(len(brand), 1)) * 100),
                evidence=f'Domain closely resembles "{brand}" (edit distance: {dist})',
            ))
            continue

        # Brand name embedded with extra characters: amazon-secure.com
        if brand in sld_norm and sld_full not in legit_domains:
            hits.append(BrandHit(
                type="brand_in_sld",
                brand=brand,
                confidence=85,
                evidence=f'Brand "{brand}" embedded in a lookalike domain',
            ))
            continue

        # Pure homoglyph trickery: іcloud.com (Cyrillic і)
        if brand in normalized and brand not in hostname:
            hits.append(BrandHit(
                type="homoglyph_impersonation",
                brand=brand,
                confidence=96,
                evidence=f'Unicode look-alike characters used to imitate "{brand}"',
            ))

    return hits


def analyze_url(raw_url: str) -> DomainAnalysisResult:
    triggered: list[str] = []
    score = 0.03

    try:
        parsed = urlparse(raw_url)
        if not parsed.hostname:
            raise ValueError("no hostname")
    except Exception:
        return DomainAnalysisResult(score=0.95, triggered_rules=["malformed_url"])

    hostname = parsed.hostname.lower()
    full_url = raw_url.lower()
    path = (parsed.path or "").lower()

    if parsed.scheme == "http":
        score += 0.15
        triggered.append("no_https")

    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", hostname):
        score += 0.35
        triggered.append("ip_address_host")

    if hostname.count(".") >= 4:
        score += 0.2
        triggered.append("excessive_subdomains")

    tld = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        score += 0.25
        triggered.append("suspicious_tld")

    if hostname.count("-") >= 3:
        score += 0.15
        triggered.append("excessive_hyphens")

    if any(ord(c) > 127 for c in hostname):
        score += 0.4
        triggered.append("unicode_homograph")

    if "@" in full_url.split("//", 1)[-1]:
        score += 0.25
        triggered.append("at_symbol_in_url")

    if re.search(r"%2f|%5c|redirect=|returnurl=|next=|url=", full_url):
        score += 0.12
        triggered.append("encoded_redirect")

    if parsed.query and len(parsed.query.split("&")) >= 6:
        score += 0.08
        triggered.append("many_query_params")

    if re.search(r"/(login|signin|verify|secure|account/update)", path):
        score += 0.05
        triggered.append("login_path")

    brand_hits = detect_brand_impersonation(hostname)
    for hit in brand_hits:
        score += (hit.confidence / 100) * 0.45
        triggered.append(f"brand_impersonation:{hit.brand}:{hit.type}")

    kw_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in full_url)
    if kw_hits >= 3:
        score += 0.2
        triggered.append(f"phishing_keywords:{kw_hits}")

    if len(raw_url) > 200:
        score += 0.1
        triggered.append("long_url")

    return DomainAnalysisResult(
        score=min(round(score, 3), 1.0),
        triggered_rules=triggered,
        brand_hits=brand_hits,
    )
