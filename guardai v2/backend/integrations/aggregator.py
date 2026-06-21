"""
GuardAI Backend — Threat Intelligence Aggregator

Unified interface used by the /analyze route. Runs all configured providers
concurrently with asyncio.gather, tolerates individual provider failures
(each provider already swallows its own exceptions and circuit-breaks),
and returns a flat, deduplicated list of ThreatIntelHit evidence.
"""

import asyncio
import logging

from integrations.base import ThreatIntelHit
from integrations.domain_age import DomainAgeProvider
from integrations.google_safe_browsing import GoogleSafeBrowsingProvider
from integrations.openphish import OpenPhishProvider
from integrations.phishtank import PhishTankProvider

logger = logging.getLogger("guardai.integrations.aggregator")

_providers = [
    GoogleSafeBrowsingProvider(),
    OpenPhishProvider(),
    PhishTankProvider(),
    DomainAgeProvider(),
]


async def check_all_providers(url: str) -> list[ThreatIntelHit]:
    """
    Query every threat intel provider concurrently.
    Never raises — a provider failure simply yields no hits from that source.
    """
    results = await asyncio.gather(
        *(provider.check_url(url) for provider in _providers),
        return_exceptions=True,
    )

    hits: list[ThreatIntelHit] = []
    for provider, result in zip(_providers, results):
        if isinstance(result, Exception):
            logger.error("Provider %s raised unexpectedly: %s", provider.name, result)
            continue
        hits.extend(result)

    return hits


async def providers_health() -> list[dict]:
    return await asyncio.gather(*(p.health() for p in _providers))
