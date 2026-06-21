"""
GuardAI Backend — Threat Intelligence: Domain Age (RDAP)

Checks how recently a domain was registered, via RDAP (Registration Data
Access Protocol, RFC 9083) — the modern, free, no-API-key successor to
WHOIS. This is the specific signal that catches a brand-new scam shop
that doesn't impersonate any existing brand (so brand_impersonation in
domain_analysis.py wouldn't flag it) and hasn't been reported to any
blocklist yet (so threat intel in google_safe_browsing/openphish/phishtank
wouldn't flag it either). A domain registered hours or days ago is one of
the single strongest signals of a freshly-spun-up scam page.

How it works:
  1. Query https://rdap.org/domain/<domain> — a free public bootstrap
     service that resolves to the correct authoritative registry RDAP
     server for any TLD (no API key, no rate-limit tier to manage).
  2. Parse the "events" array for an entry with eventAction == "registration".
  3. Compute domain age in days; surface as a ThreatIntelHit if very new.

IMPORTANT — read before trusting this in production:
This integration follows the published RDAP spec (RFC 9083) exactly, but
it has NOT been tested against live traffic from within this build's
environment — the sandbox used to develop GuardAI has a restricted
network egress allowlist that does not include rdap.org or any registry
RDAP server, so live HTTP calls could not be made or verified here. The
parsing logic, circuit breaker, caching, and fail-safe behavior (returns
no hit rather than crashing if RDAP is unreachable or the domain isn't
found) follow the same tested patterns as the other three threat-intel
integrations in this directory. Run it yourself once deployed and confirm
a known-new domain and a known-old domain (e.g. google.com) both return
sane ages — see the verification snippet in this module's docstring
below.

Verification snippet (run after deploying, with internet access):
    import asyncio
    from integrations.domain_age import DomainAgeProvider
    async def test():
        p = DomainAgeProvider()
        print(await p.check_url("https://google.com"))       # should be no hit (old domain)
        print(await p.check_url("https://example.com"))      # should be no hit (old domain)
    asyncio.run(test())
"""

import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.cache import cache_get, cache_set
from core.circuit_breaker import CircuitBreaker
from core.config import settings
from core.http_client import get_http_client
from integrations.base import ThreatIntelHit, ThreatIntelProvider

logger = logging.getLogger("guardai.integrations.domain_age")

RDAP_BOOTSTRAP_ENDPOINT = "https://rdap.org/domain/{domain}"

# Thresholds for flagging — tuned conservatively to avoid false-flagging
# legitimately new (but real) small businesses too aggressively. A
# brand-new domain isn't proof of a scam, but it's strong corroborating
# evidence, especially combined with other signals (no other site links
# to it, generic "shop" branding, aggressive social-media ad pushing).
VERY_NEW_DAYS = 7      # registered within the last week — strong signal
NEW_DAYS = 30          # registered within the last month — moderate signal


class DomainAgeProvider(ThreatIntelProvider):
    name = "Domain Age (RDAP)"

    def __init__(self):
        self._breaker = CircuitBreaker(
            name="domain_age_rdap",
            failure_threshold=settings.CB_FAILURE_THRESHOLD,
            recovery_seconds=settings.CB_RECOVERY_SEC,
        )

    def _extract_registration_date(self, rdap_data: dict) -> datetime | None:
        """Parse the RFC 9083 'events' array for the registration event."""
        events = rdap_data.get("events", [])
        for event in events:
            if event.get("eventAction") == "registration":
                date_str = event.get("eventDate")
                if not date_str:
                    continue
                try:
                    # RDAP dates are ISO 8601, e.g. "1992-01-01T00:00:00+00:00"
                    # or with "Z" suffix — normalize "Z" to "+00:00" for fromisoformat
                    normalized = date_str.replace("Z", "+00:00")
                    return datetime.fromisoformat(normalized)
                except (ValueError, TypeError):
                    logger.debug("Could not parse RDAP eventDate: %s", date_str)
                    continue
        return None

    async def check_url(self, url: str) -> list[ThreatIntelHit]:
        try:
            hostname = urlparse(url).hostname
        except Exception:
            return []

        if not hostname:
            return []

        # Strip to registrable domain heuristically (e.g. shop.example.com -> example.com)
        # for the RDAP query — registries hold registration data at this level, not
        # for arbitrary subdomains. This is a simple heuristic, not full PSL parsing;
        # acceptable here since we only need "approximately right" for an age signal.
        parts = hostname.lower().split(".")
        registrable_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        cache_key = f"domain_age:{registrable_domain}"
        cached = await cache_get(cache_key)
        if cached is not None:
            return [ThreatIntelHit(**hit) for hit in cached]

        if not await self._breaker.allow_request():
            logger.debug("Domain age (RDAP) circuit open — skipping")
            return []

        try:
            session = get_http_client()
            headers = {"Accept": "application/rdap+json"}
            endpoint = RDAP_BOOTSTRAP_ENDPOINT.format(domain=registrable_domain)

            async with session.get(endpoint, headers=headers) as resp:
                if resp.status == 404:
                    # Domain not found in RDAP — not an error, just no data available
                    await self._breaker.record_success()
                    await cache_set(cache_key, [], settings.CACHE_TTL_URL_SEC)
                    return []
                if resp.status != 200:
                    await self._breaker.record_failure()
                    return []

                data = await resp.json(content_type=None)
                await self._breaker.record_success()

                registration_date = self._extract_registration_date(data)
                if registration_date is None:
                    # Some ccTLD registries (e.g. .de) don't publish creation dates —
                    # this is registry policy, not an error. No hit, no penalty.
                    await cache_set(cache_key, [], settings.CACHE_TTL_URL_SEC)
                    return []

                now = datetime.now(timezone.utc)
                age_days = (now - registration_date).days

                if age_days < 0:
                    # Clock skew or future-dated event — don't trust it
                    return []

                hits = []
                if age_days <= VERY_NEW_DAYS:
                    hits.append(ThreatIntelHit(
                        source=self.name,
                        threat="newly_registered_domain",
                        confidence=70,
                        detail=f"Domain registered only {age_days} day(s) ago",
                    ))
                elif age_days <= NEW_DAYS:
                    hits.append(ThreatIntelHit(
                        source=self.name,
                        threat="recently_registered_domain",
                        confidence=40,
                        detail=f"Domain registered {age_days} days ago",
                    ))

                # Cache for longer than other providers — domain age changes slowly
                await cache_set(
                    cache_key,
                    [h.to_dict() | {"raw": {}} for h in hits],
                    settings.CACHE_TTL_FEED_SEC,
                )
                return hits

        except asyncio.TimeoutError:
            await self._breaker.record_failure()
            logger.warning("RDAP request timed out for %s", registrable_domain)
            return []
        except Exception as exc:
            await self._breaker.record_failure()
            logger.error("RDAP lookup error for %s: %s", registrable_domain, exc)
            return []

    async def health(self) -> dict:
        return {
            "name": self.name,
            "thresholds_days": {"very_new": VERY_NEW_DAYS, "new": NEW_DAYS},
            **self._breaker.status(),
        }
