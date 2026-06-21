"""
GuardAI Backend — Shared aiohttp ClientSession

A single pooled session is reused across all outbound requests (Google Safe
Browsing, OpenPhish, PhishTank, domain-age lookups) to avoid the overhead of
opening a new TCP/TLS connection per request.
"""

import aiohttp

from core.config import settings

_session: aiohttp.ClientSession | None = None


async def init_http_client() -> None:
    global _session
    timeout = aiohttp.ClientTimeout(total=settings.HTTP_TIMEOUT_SEC)
    connector = aiohttp.TCPConnector(limit=100, limit_per_host=20, ttl_dns_cache=300)
    _session = aiohttp.ClientSession(timeout=timeout, connector=connector)


async def close_http_client() -> None:
    global _session
    if _session is not None:
        await _session.close()
        _session = None


def get_http_client() -> aiohttp.ClientSession:
    if _session is None:
        raise RuntimeError("HTTP client not initialized — call init_http_client() at startup")
    return _session
