"""
GuardAI Backend — Threat Intelligence: PhishTank

Docs: https://www.phishtank.com/api_info.php

PhishTank's checkurl API expects a url-encoded POST. An application key
(PHISHTANK_API_KEY) raises the rate limit substantially — strongly
recommended before public beta launch to avoid being throttled.
"""

import asyncio
import logging

from core.cache import cache_get, cache_set
from core.circuit_breaker import CircuitBreaker
from core.config import settings
from core.http_client import get_http_client
from integrations.base import ThreatIntelHit, ThreatIntelProvider

logger = logging.getLogger("guardai.integrations.phishtank")

PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"


class PhishTankProvider(ThreatIntelProvider):
    name = "PhishTank"

    def __init__(self):
        self._breaker = CircuitBreaker(
            name="phishtank",
            failure_threshold=settings.CB_FAILURE_THRESHOLD,
            recovery_seconds=settings.CB_RECOVERY_SEC,
        )

    async def check_url(self, url: str) -> list[ThreatIntelHit]:
        cache_key = f"phishtank:{url}"
        cached = await cache_get(cache_key)
        if cached is not None:
            return [ThreatIntelHit(**hit) for hit in cached]

        if not await self._breaker.allow_request():
            logger.debug("PhishTank circuit open — skipping")
            return []

        try:
            session = get_http_client()
            data = {"url": url, "format": "json"}
            if settings.PHISHTANK_API_KEY:
                data["app_key"] = settings.PHISHTANK_API_KEY

            headers = {"User-Agent": "GuardAI/0.2.0 (phishing-detection-extension)"}

            async with session.post(PHISHTANK_ENDPOINT, data=data, headers=headers) as resp:
                if resp.status == 509:
                    # PhishTank rate-limit response code
                    await self._breaker.record_failure()
                    logger.warning("PhishTank rate limit exceeded")
                    return []
                if resp.status != 200:
                    await self._breaker.record_failure()
                    return []

                body = await resp.json(content_type=None)
                await self._breaker.record_success()

                results = body.get("results", {})
                if not results.get("in_database"):
                    await cache_set(cache_key, [], settings.CACHE_TTL_URL_SEC)
                    return []

                is_phish = results.get("valid") and results.get("verified")
                if not is_phish:
                    await cache_set(cache_key, [], settings.CACHE_TTL_URL_SEC)
                    return []

                hit = ThreatIntelHit(
                    source=self.name,
                    threat="phishing",
                    confidence=95,
                    detail="Verified phishing URL in PhishTank community database",
                )
                await cache_set(cache_key, [hit.to_dict()], settings.CACHE_TTL_URL_SEC)
                return [hit]

        except asyncio.TimeoutError:
            await self._breaker.record_failure()
            logger.warning("PhishTank request timed out")
            return []
        except Exception as exc:
            await self._breaker.record_failure()
            logger.error("PhishTank error: %s", exc)
            return []

    async def health(self) -> dict:
        return {
            "name": self.name,
            "configured_with_key": bool(settings.PHISHTANK_API_KEY),
            **self._breaker.status(),
        }
