"""
GuardAI Backend  v0.2.0
FastAPI application entry point.

Startup order:
  1. Load config / secrets from environment
  2. Initialize HTTP client pool (aiohttp)
  3. Mount routers
  4. Register middleware (rate limit, request ID, security headers)
"""

import logging
import os
import uuid
from contextlib import asynccontextmanager

import aiohttp
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from core.http_client import init_http_client, close_http_client
from middleware.rate_limit import RateLimitMiddleware
from middleware.security_headers import SecurityHeadersMiddleware
from routers import analyze, health, metrics

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("guardai")


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start/stop shared resources."""
    logger.info("GuardAI backend starting — env=%s", settings.ENV)
    await init_http_client()
    yield
    await close_http_client()
    logger.info("GuardAI backend shut down cleanly.")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="GuardAI API",
    version="0.2.0",
    docs_url="/docs" if settings.ENV != "production" else None,   # hide Swagger in prod
    redoc_url=None,
    openapi_url="/openapi.json" if settings.ENV != "production" else None,
    lifespan=lifespan,
)

# ── Middleware (order matters — outermost is first) ───────────────────────────

# 1. CORS — allow only the Chrome extension origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "X-Extension-Version", "X-Request-ID"],
)

# 2. Security headers
app.add_middleware(SecurityHeadersMiddleware)

# 3. Rate limiting (per-IP sliding window)
app.add_middleware(RateLimitMiddleware)


# ── Request ID injection ──────────────────────────────────────────────────────

@app.middleware("http")
async def inject_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response   = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ── Global error handler ──────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "request_id": request.headers.get("X-Request-ID", "")},
    )


# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(analyze.router,  prefix="/v1")
app.include_router(health.router,   prefix="/v1")
app.include_router(metrics.router,  prefix="/v1")
