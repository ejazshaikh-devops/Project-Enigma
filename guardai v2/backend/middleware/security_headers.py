"""
GuardAI Backend — Security Headers Middleware

Applies standard hardening headers to every response. Defense-in-depth:
this is an API (not a browser-rendered app) but these headers cost nothing
and protect against edge cases (e.g. someone embedding /docs in an iframe,
browsers MIME-sniffing a JSON error page).
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response
