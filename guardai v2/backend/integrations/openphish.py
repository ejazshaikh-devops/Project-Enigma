"""
GuardAI Backend — Threat Intelligence: OpenPhish

OpenPhish's free feed is a plaintext list of known phishing URLs, refreshed
periodically (https://openphish.com/feed.txt). We poll it on a TTL and keep
the parsed set in cache for fast in-process matching — this avoids one
HTTP round trip per URL check.
"""

import asyncio
import logging

from core.cache import cache_get, cache_set
from core.circuit_breaker import CircuitBreaker
from core.config import settings
from core.http_client import get_http_client
from integrations.base import ThreatIntelHit, ThreatIntelProvider

logger = logging.getLogger("guardai.integrations.openphish")

FEED_CACHE_KEY = "openphish:feed"


class OpenPhishProvider(ThreatIntelProvider):
    name = "OpenPhish"

    def __init__(self):
        self._breaker = CircuitBreaker(
            name="openphish",
            failure_threshold=settings.CB_FAILURE_THRESHOLD,
            recovery_seconds=settings.CB_RECOVERY_SEC,
        )
        self._local_set: set[str] | None = None

    async def _refresh_feed(self) -> set[str]:
        cached = await cache_get(FEED_CACHE_KEY)
        if cached is not None:
            self._local_set = set(cached)
            return self._local_set

        if not await self._breaker.allow_request():
            logger.debug("OpenPhish circuit open — using stale local set if available")
            return self._local_set or set()

        try:
            session = get_http_client()
            async with session.get(settings.OPENPHISH_FEED_URL) as resp:
                if resp.status != 200:
                    await self._breaker.record_failure()
                    return self._local_set or set()
                text = await resp.text()
                urls = {line.strip() for line in text.splitlines() if line.strip()}
                await self._breaker.record_success()

                # Cap stored feed size for memory safety on free-tier infra
                trimmed = set(list(urls)[:50_000])
                await cache_set(FEED_CACHE_KEY, list(trimmed), settings.CACHE_TTL_FEED_SEC)
                self._local_set = trimmed
                logger.info("OpenPhish feed refreshed: %d entries", len(trimmed))
                return trimmed

        except asyncio.TimeoutError:
            await self._breaker.record_failure()
            logger.warning("OpenPhish feed fetch timed out")
            return self._local_set or set()
        except Exception as exc:
            await self._breaker.record_failure()
            logger.error("OpenPhish feed error: %s", exc)
            return self._local_set or set()

    async def check_url(self, url: str) -> list[ThreatIntelHit]:
        feed = await self._refresh_feed()
        if not feed:
            return []

        # Exact match + prefix match (OpenPhish entries are often full URLs incl. path)
        normalized = url.rstrip("/")
        for entry in feed:
            if normalized == entry.rstrip("/") or normalized.startswith(entry.rstrip("/")):
                return [
                    ThreatIntelHit(
                        source=self.name,
                        threat="phishing",
                        confidence=92,
                        detail="URL matches an active entry in the OpenPhish feed",
                    )
                ]
        return []

    async def health(self) -> dict:
        return {
            "name": self.name,
            "feed_size": len(self._local_set or []),
            **self._breaker.status(),
        }
