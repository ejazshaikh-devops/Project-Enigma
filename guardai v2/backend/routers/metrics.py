"""
GuardAI Backend — /v1/metrics

Exposes aggregate, privacy-preserving usage metrics: scans performed,
threats blocked, verdict distribution, extension version spread, and API
latency. No URLs or per-user data are ever exposed here.

In production, protect this endpoint behind an internal-only network path
(VPC, ALB rule) or an admin API key — it's operational data, not meant to
be public, even though it contains no sensitive content.
"""

from fastapi import APIRouter, Header, HTTPException

from core.config import settings
from services.telemetry import get_snapshot, record_extension_version

router = APIRouter()


@router.get("/metrics")
async def metrics(x_admin_key: str | None = Header(default=None)):
    # Lightweight gate: if EXTENSION_SHARED_SECRET is configured, require it
    # here too so metrics aren't fully public in production.
    if settings.ENV == "production" and settings.EXTENSION_SHARED_SECRET:
        if x_admin_key != settings.EXTENSION_SHARED_SECRET:
            raise HTTPException(status_code=403, detail="Forbidden")

    return get_snapshot()


@router.post("/metrics/version")
async def report_version(version: str):
    """Extension calls this on startup to report its version for adoption tracking."""
    record_extension_version(version)
    return {"ok": True}
