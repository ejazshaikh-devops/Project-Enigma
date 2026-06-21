"""
GuardAI Backend — Rate Limit Middleware

Simple in-process sliding-window rate limiter keyed by client IP.
Good enough for a single-instance beta deployment. For multi-instance
production (App Runner auto-scaling), back this with Redis (INCR + EXPIRE)
so limits are enforced consistently across instances — see note below.

NOTE: When REDIS_URL is configured, this still uses the in-memory window
per-instance. Before scaling beyond 1 instance, swap _hits for a Redis-backed
counter to get a globally consistent rate limit.
"""

import time
import logging
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from core.config import settings

logger = logging.getLogger("guardai.middleware.rate_limit")

# client_ip -> deque[timestamps]
_hits: dict[str, deque] = defaultdict(deque)

EXEMPT_PATHS = {"/v1/health", "/v1/health/", "/docs", "/openapi.json"}


def _client_ip(request: Request) -> str:
    # Trust X-Forwarded-For only if behind a known proxy/load balancer (App Runner/ALB).
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        ip = _client_ip(request)
        now = time.monotonic()
        window = settings.RATE_LIMIT_WINDOW_SEC
        limit = settings.RATE_LIMIT_REQUESTS

        bucket = _hits[ip]
        while bucket and now - bucket[0] > window:
            bucket.popleft()

        if len(bucket) >= limit:
            logger.warning("Rate limit exceeded for %s", ip)
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded. Please slow down.", "retry_after_seconds": window},
                headers={"Retry-After": str(window)},
            )

        bucket.append(now)

        # Periodically prevent unbounded growth of the IP dict
        if len(_hits) > 100_000:
            _hits.clear()

        return await call_next(request)
