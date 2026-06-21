"""
GuardAI Backend — /v1/analyze

The core endpoint the extension calls for every navigation. Combines:
  1. Server-side authoritative domain/brand analysis (does not trust client score)
  2. Threat intelligence aggregation (Google Safe Browsing, OpenPhish, PhishTank)
  3. ML classifiers — two independent models:
       a. Pre-trained LinearSVM (pirocheto/phishing-url-detection, MIT
          license, trained on a real 11k+ URL dataset) — used when
          downloaded via ml/download_pretrained_model.py, preferred when
          available since it's trained on real data, not synthetic
       b. Synthetic logistic regression (ml/train_model.py) — always
          available as a fallback, see ml/README.md for its honest
          limitations
  4. Explainable verdict construction (verdict, confidence, reasons, triggered_rules)
"""

import logging
import time

from fastapi import APIRouter, Request

from core.domain_analysis import analyze_url
from integrations.aggregator import check_all_providers
from ml.predict import explain_prediction, predict_phishing_probability
from ml.pretrained_predict import predict_pretrained_probability
from models.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    BrandHitResponse,
    ThreatIntelHitResponse,
)
from services.telemetry import record_extension_version, record_latency, record_scan
from services.verdict import build_verdict

logger = logging.getLogger("guardai.routers.analyze")

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest, request: Request):
    request_id = request.headers.get("X-Request-ID", "")
    ext_version = request.headers.get("X-Extension-Version", "")
    if ext_version:
        record_extension_version(ext_version)

    t0 = time.monotonic()

    # 1. Authoritative server-side analysis — never trust client-reported score alone
    domain_result = analyze_url(payload.url)

    # 2. Threat intelligence (concurrent, fault-tolerant)
    ti_hits = await check_all_providers(payload.url)

    # 3. ML classifiers — two independent signals, each optional.
    #    Both return None (not 0.0) when unavailable, so a missing model
    #    never silently drags the score down — it's just excluded.
    pretrained_probability = predict_pretrained_probability(payload.url)
    synthetic_probability = predict_phishing_probability(payload.url)
    ml_reasons = explain_prediction(payload.url) if synthetic_probability is not None else []

    # The "ai_score" surfaced to the client prefers the pre-trained model
    # (trained on real data) when available, falling back to the
    # synthetic model otherwise.
    ml_probability = pretrained_probability if pretrained_probability is not None else synthetic_probability

    # 4. Combine into final risk score.
    #    Not all threat-intel hits carry equal weight:
    #      - A verified match from Google Safe Browsing, OpenPhish, or
    #        PhishTank means the URL is a KNOWN, confirmed threat —
    #        treated as near-certain.
    #      - A "newly registered domain" hit from RDAP is corroborating
    #        evidence, not proof — a brand-new domain could be a new
    #        legitimate business. It nudges the score up meaningfully
    #        but must not alone push a URL to "dangerous" the same way
    #        a confirmed blocklist match does. This matters in practice:
    #        a fresh scam shop with no brand to impersonate and no
    #        blocklist history yet would otherwise only be caught by
    #        domain age — but a new real shop shouldn't get torched for
    #        simply being new.
    VERIFIED_THREAT_SOURCES = {"Google Safe Browsing", "OpenPhish", "PhishTank"}

    verified_boost = 0.0
    corroborating_boost = 0.0
    for hit in ti_hits:
        if hit.source in VERIFIED_THREAT_SOURCES:
            verified_boost = max(verified_boost, hit.confidence / 100)
        else:
            # e.g. Domain Age (RDAP) — real signal, capped lower so it
            # combines with other weak signals rather than dominating alone
            corroborating_boost = max(corroborating_boost, (hit.confidence / 100) * 0.55)

    final_score = domain_result.score

    # The synthetic model (unlike the pre-trained one, which is trained on
    # real data) was found during testing to be unreliable in isolation on
    # short, low-signal URLs — e.g. https://google.com/ scored as high as
    # 76% phishing purely from URL length, with zero corroborating risk
    # signal. Root cause: a 21-feature linear model has very little to go
    # on for a bare, clean domain, and sits close to its decision boundary
    # by construction in that regime (see ml/README.md for the full
    # writeup). Rather than chase this domain-by-domain in training data
    # indefinitely, the synthetic model's score is only trusted at full
    # strength when at least one independent signal corroborates it — a
    # triggered rule, a brand-impersonation hit, or the pre-trained model
    # (which doesn't share this failure mode) agreeing. With zero
    # corroboration, its influence is capped well below the "suspicious"
    # threshold so it can nudge but not single-handedly flag a clean URL.
    has_corroboration = bool(domain_result.triggered_rules) or bool(domain_result.brand_hits)

    if pretrained_probability is not None:
        final_score = max(final_score, pretrained_probability)
        has_corroboration = has_corroboration or pretrained_probability >= 0.5

    if synthetic_probability is not None:
        if has_corroboration:
            final_score = max(final_score, synthetic_probability)
        else:
            final_score = max(final_score, min(synthetic_probability, 0.35))

    if corroborating_boost > 0:
        final_score = max(final_score, corroborating_boost)
    if verified_boost > 0:
        # Confirmed blocklist match dominates — treat as near-certain
        final_score = max(final_score, min(0.99, verified_boost))

    final_score = round(min(final_score, 1.0), 3)

    all_triggered_rules = list(domain_result.triggered_rules)

    verdict_obj = build_verdict(
        score=final_score,
        triggered_rules=all_triggered_rules,
        brand_hits=domain_result.brand_hits,
        threat_intel_hits=ti_hits,
    )

    # Surface ML-driven reasons too, but only when the model actually
    # contributed meaningfully (kept separate from rule reasons so it's
    # clear in the response which signal said what)
    if pretrained_probability is not None and pretrained_probability >= 0.5 and verdict_obj["verdict"] != "safe":
        verdict_obj["reasons"].insert(0, "Pre-trained AI model flagged this URL as likely phishing")
    if ml_reasons and verdict_obj["verdict"] != "safe":
        verdict_obj["reasons"] = (verdict_obj["reasons"] + ml_reasons)[:6]

    record_scan(verdict_obj["verdict"])
    record_latency((time.monotonic() - t0) * 1000)

    return AnalyzeResponse(
        verdict=verdict_obj["verdict"],
        confidence=verdict_obj["confidence"],
        risk_score=final_score,
        reasons=verdict_obj["reasons"],
        triggered_rules=verdict_obj["triggered_rules"],
        ai_score=round(ml_probability * 100) if ml_probability is not None else None,
        threat_intel=[ThreatIntelHitResponse(**h.to_dict()) for h in ti_hits],
        brand_hits=[
            BrandHitResponse(type=b.type, brand=b.brand, confidence=b.confidence, evidence=b.evidence)
            for b in domain_result.brand_hits
        ],
        request_id=request_id,
    )
