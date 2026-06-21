"""
GuardAI Backend — Verdict Construction Service

Turns raw scores + triggered rules + threat intel hits into the explainable
verdict contract the extension and any future dashboard rely on:
  verdict, confidence, reasons, triggered_rules, ai_score
"""

from core.domain_analysis import BrandHit
from integrations.base import ThreatIntelHit

RISK_WARN = 0.5
RISK_BLOCK = 0.85

RULE_LABELS = {
    "no_https": "Connection is not encrypted (HTTP)",
    "ip_address_host": "IP address used instead of a domain name",
    "excessive_subdomains": "Suspicious chain of subdomains",
    "suspicious_tld": "High-risk top-level domain extension",
    "excessive_hyphens": "Domain contains an unusual number of hyphens",
    "unicode_homograph": "Non-standard characters used to mimic a real domain",
    "at_symbol_in_url": "Hidden destination trick using @ symbol",
    "encoded_redirect": "URL contains a redirect pattern",
    "many_query_params": "Unusually high number of URL parameters",
    "login_path": "URL path contains login or verification keywords",
    "long_url": "URL is excessively long",
    "malformed_url": "URL is malformed and cannot be parsed",
}


def _label_rule(rule: str) -> str:
    if rule in RULE_LABELS:
        return RULE_LABELS[rule]
    if rule.startswith("brand_impersonation:"):
        parts = rule.split(":")
        brand = parts[1] if len(parts) > 1 else "a known brand"
        return f'Brand impersonation detected: "{brand}"'
    if rule.startswith("phishing_keywords:"):
        count = rule.split(":")[-1]
        return f"{count} phishing-related keywords found in URL"
    return rule


def build_verdict(
    score: float,
    triggered_rules: list[str],
    brand_hits: list[BrandHit],
    threat_intel_hits: list[ThreatIntelHit],
) -> dict:
    reasons: list[str] = []
    triggered_labels: list[str] = [_label_rule(r) for r in triggered_rules]

    # Threat intel reasons take priority — they're the strongest signal
    for hit in threat_intel_hits:
        reasons.append(f"Flagged by {hit.source}: {hit.detail or hit.threat}")

    # Brand impersonation evidence
    for hit in brand_hits:
        reasons.append(hit.evidence)

    # Fall back to local heuristic labels if nothing else explains the score
    if not reasons:
        reasons.extend(triggered_labels[:5])

    if score >= RISK_BLOCK:
        verdict = "dangerous"
    elif score >= RISK_WARN:
        verdict = "suspicious"
    else:
        verdict = "safe"
        if not reasons:
            reasons = ["No threats detected — domain passed all security checks"]

    confidence = round(score * 100)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reasons": reasons if reasons else ["No threats detected"],
        "triggered_rules": triggered_labels,
    }
