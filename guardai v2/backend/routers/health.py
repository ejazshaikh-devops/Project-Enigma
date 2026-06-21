"""
GuardAI Backend — /v1/health

Liveness/readiness endpoint for AWS App Runner health checks and uptime
monitoring. Also surfaces threat-intel provider circuit breaker status so
on-call engineers can see degraded providers at a glance, and confirms
whether the ML model loaded successfully.
"""

from fastapi import APIRouter

from integrations.aggregator import providers_health
from ml.predict import model_info
from ml.pretrained_predict import pretrained_model_info

router = APIRouter()


@router.get("/health")
async def health():
    providers = await providers_health()
    overall_healthy = True  # liveness should stay healthy even if a 3rd-party provider is degraded
    return {
        "status": "ok" if overall_healthy else "degraded",
        "version": "0.2.0",
        "providers": providers,
        "ml_model": model_info(),
        "ml_pretrained_model": pretrained_model_info(),
    }


@router.get("/health/live")
async def liveness():
    """Minimal liveness probe — no downstream calls. Used by App Runner health check."""
    return {"status": "ok"}
