"""
GuardAI Backend — Configuration

All secrets and environment-specific values come from environment variables.
NEVER hardcode API keys, database URLs, or secrets in source code.

In production (AWS App Runner / ECS), inject these via:
  - AWS Secrets Manager (preferred for API keys)
  - App Runner environment variable configuration
"""

import os
from functools import lru_cache
from typing import List


def _split_csv(value: str) -> List[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


class Settings:
    # ── Environment ──────────────────────────────────────────────────────────
    ENV: str = os.getenv("GUARDAI_ENV", "development")  # development | staging | production

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Chrome extensions call from chrome-extension://<id> origins.
    # Set GUARDAI_EXTENSION_ID in env after publishing to the Chrome Web Store.
    _extension_id: str = os.getenv("GUARDAI_EXTENSION_ID", "")
    ALLOWED_ORIGINS: List[str] = (
        _split_csv(os.getenv("GUARDAI_ALLOWED_ORIGINS", ""))
        or ([f"chrome-extension://{_extension_id}"] if _extension_id else [])
    )

    # ── Threat Intelligence API Keys (set via Secrets Manager / env) ─────────
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    PHISHTANK_API_KEY: str            = os.getenv("PHISHTANK_API_KEY", "")  # optional, higher rate limits
    OPENPHISH_FEED_URL: str           = os.getenv(
        "OPENPHISH_FEED_URL", "https://openphish.com/feed.txt"
    )

    # ── Rate Limiting ────────────────────────────────────────────────────────
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
    RATE_LIMIT_WINDOW_SEC: int = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))

    # ── Caching ──────────────────────────────────────────────────────────────
    REDIS_URL: str = os.getenv("REDIS_URL", "")  # empty = use in-memory cache fallback
    CACHE_TTL_URL_SEC: int  = int(os.getenv("CACHE_TTL_URL_SEC", "300"))
    CACHE_TTL_FEED_SEC: int = int(os.getenv("CACHE_TTL_FEED_SEC", "900"))

    # ── Circuit Breaker ──────────────────────────────────────────────────────
    CB_FAILURE_THRESHOLD: int = int(os.getenv("CB_FAILURE_THRESHOLD", "3"))
    CB_RECOVERY_SEC: int      = int(os.getenv("CB_RECOVERY_SEC", "60"))

    # ── HTTP Client ──────────────────────────────────────────────────────────
    HTTP_TIMEOUT_SEC: float = float(os.getenv("HTTP_TIMEOUT_SEC", "6.0"))

    # ── Domain age lookup (e.g. WHOIS / RDAP provider) ───────────────────────
    DOMAIN_AGE_API_KEY: str = os.getenv("DOMAIN_AGE_API_KEY", "")
    DOMAIN_AGE_API_URL: str = os.getenv("DOMAIN_AGE_API_URL", "")

    # ── Auth (service-to-service, extension → backend) ───────────────────────
    # Lightweight HMAC shared secret to ensure requests come from the real extension,
    # NOT a substitute for full user auth (this product has no user accounts yet).
    EXTENSION_SHARED_SECRET: str = os.getenv("EXTENSION_SHARED_SECRET", "")

    # ── Telemetry ────────────────────────────────────────────────────────────
    TELEMETRY_ENABLED: bool = os.getenv("TELEMETRY_ENABLED", "true").lower() == "true"

    # ── AWS ──────────────────────────────────────────────────────────────────
    AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")

    def validate(self) -> List[str]:
        """Return a list of configuration warnings (non-fatal) for startup logging."""
        warnings = []
        if self.ENV == "production":
            if not self.ALLOWED_ORIGINS:
                warnings.append("GUARDAI_ALLOWED_ORIGINS / GUARDAI_EXTENSION_ID not set — CORS will block all requests")
            if not self.GOOGLE_SAFE_BROWSING_API_KEY:
                warnings.append("GOOGLE_SAFE_BROWSING_API_KEY not set — Safe Browsing checks disabled")
            if not self.EXTENSION_SHARED_SECRET:
                warnings.append("EXTENSION_SHARED_SECRET not set — request authenticity check disabled")
            if not self.REDIS_URL:
                warnings.append("REDIS_URL not set — using in-memory cache (will not work across multiple instances)")
        return warnings


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
