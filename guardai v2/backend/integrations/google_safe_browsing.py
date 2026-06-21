"""
GuardAI Backend — Threat Intelligence: Google Safe Browsing

Docs: https://developers.google.com/safe-browsing/v4/lookup-api

Uses the Lookup API (threatMatches:find) — simple per-URL check, no need to
maintain local hash-prefix database. Good fit for a low/medium traffic beta.
At higher volume, migrate to the Update API (local hash database) to avoid
sending every URL to Google.
"""

import asyncio
import hashlib
import logging

from core.cache import cache_get, cache_set
from core.circuit_breaker import CircuitBreaker
from core.config import settings
from core.http_client import get_http_client
from integrations.base import ThreatIntelHit, ThreatIntelProvider

logger = logging.getLogger("guardai.integrations.safebrowsing")

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

THREAT_TYPE_LABELS = {
    "MALWARE": "Malware",
    "SOCIAL_ENGINEERING": "Phishing / Social Engineering",
    "UNWANTED_SOFTWARE": "Unwanted Software",
    "POTENTIALLY_HARMFUL_APPLICATION": "Potentially Harmful Application",
}


class GoogleSafeBrowsingProvider(ThreatIntelProvider):
    name = "Google Safe Browsing"

    def __init__(self):
        self._breaker = CircuitBreaker(
            name="google_safe_browsing",
            failure_threshold=settings.CB_FAILURE_THRESHOLD,
            recovery_seconds=settings.CB_RECOVERY_SEC,
        )

    async def check_url(self, url: str) -> list[ThreatIntelHit]:
        if not settings.GOOGLE_SAFE_BROWSING_API_KEY:
            return []  # not configured — silently skip, don't fail the whole request

        cache_key = f"gsb:{hashlib.sha256(url.encode()).hexdigest()}"
        cached = await cache_get(cache_key)
        if cached is not None:
            return [ThreatIntelHit(**hit) for hit in cached]

        if not await self._breaker.allow_request():
            logger.debug("Google Safe Browsing circuit open — skipping")
            return []

        try:
            session = get_http_client()
            payload = {
                "client": {"clientId": "guardai", "clientVersion": "0.2.0"},
                "threatInfo": {
                    "threatTypes": list(THREAT_TYPE_LABELS.keys()),
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            async with session.post(
                SAFE_BROWSING_ENDPOINT,
                params={"key": settings.GOOGLE_SAFE_BROWSING_API_KEY},
                json=payload,
            ) as resp:
                if resp.status != 200:
                    await self._breaker.record_failure()
                    logger.warning("Google Safe Browsing returned HTTP %d", resp.status)
                    return []

                data = await resp.json()
                await self._breaker.record_success()

                matches = data.get("matches", [])
                hits = [
                    ThreatIntelHit(
                        source=self.name,
                        threat=m.get("threatType", "UNKNOWN"),
                        confidence=98,
                        detail=THREAT_TYPE_LABELS.get(m.get("threatType"), m.get("threatType")),
                        raw=m,
                    )
                    for m in matches
                ]

                await cache_set(cache_key, [h.to_dict() | {"raw": {}} for h in hits], settings.CACHE_TTL_URL_SEC)
                return hits

        except asyncio.TimeoutError:
            await self._breaker.record_failure()
            logger.warning("Google Safe Browsing request timed out")
            return []
        except Exception as exc:
            await self._breaker.record_failure()
            logger.error("Google Safe Browsing error: %s", exc)
            return []

    async def health(self) -> dict:
        return {
            "name": self.name,
            "configured": bool(settings.GOOGLE_SAFE_BROWSING_API_KEY),
            **self._breaker.status(),
        }
