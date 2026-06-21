# GuardAI — System Architecture (Phase 2)

## Overview

GuardAI is a two-part system: a Chrome MV3 extension (client) and a FastAPI
backend (server) deployed on AWS App Runner. The extension performs fast
local heuristics on every navigation and asks the backend for an
authoritative, threat-intel-enriched verdict asynchronously, so the user
never waits on a network round trip to get *some* signal.

## Components

### 1. Chrome Extension (Manifest V3)

| File | Responsibility |
|------|------------------|
| `background/worker.js` | Service worker. Runs local URL heuristics + brand impersonation detection on every navigation, calls the backend, caches results, manages the toolbar badge, handles circuit breaking on the client side too. |
| `content/detector.js` | Inspects page DOM for password/payment/crypto fields, external form actions, and suspicious language — sends only boolean/count signals, never page text, to the background worker. |
| `content/formWatcher.js` | Intercepts password-form submissions on risky pages and shows an in-page warning banner; protects crypto seed-phrase fields with a dedicated warning. |
| `popup/` | Displays the explainable verdict: verdict, confidence, reasons, triggered rules, threat intel hits. |

**Permissions are least-privilege**: `tabs`, `webNavigation`, `storage`,
`alarms`, and `host_permissions` scoped to exactly two backend hostnames
(production + staging). No `<all_urls>` host permission — only the content
script match pattern needs broad page access, which is intrinsic to the
product's purpose.

### 2. FastAPI Backend

| Module | Responsibility |
|--------|------------------|
| `main.py` | App assembly: middleware chain, router mounting, global error handling, lifespan-managed HTTP client. |
| `core/config.py` | All configuration from environment variables — zero hardcoded secrets. |
| `core/domain_analysis.py` | Server-side authoritative re-implementation of URL heuristics + brand impersonation (Levenshtein, homoglyphs, Unicode normalization). Never trusts the client's self-reported score. |
| `core/circuit_breaker.py` | Generic closed/open/half-open breaker, one instance per threat-intel provider. |
| `core/cache.py` | TTL cache abstraction — Redis when configured, in-memory fallback otherwise. |
| `integrations/` | One module per threat-intel provider (Google Safe Browsing, OpenPhish, PhishTank, Domain Age/RDAP), each implementing the same `ThreatIntelProvider` interface, run concurrently via `aggregator.py`. |
| `services/verdict.py` | Combines domain analysis + threat intel into the explainable verdict contract. |
| `services/telemetry.py` | Aggregate-only counters — no URLs, no IPs, no per-user data. |
| `middleware/rate_limit.py` | Per-IP sliding window limiter. |
| `middleware/security_headers.py` | Standard hardening headers on every response. |
| `routers/analyze.py`, `health.py`, `metrics.py` | The three public API surfaces. |

### 3. Threat Intelligence Layer

Each provider is independently circuit-broken and cached, and queried
**concurrently** via `asyncio.gather(..., return_exceptions=True)` — a
single provider being slow or down never blocks or fails the overall
request. If all three providers are degraded, the system still returns a
verdict based on local domain/brand heuristics alone.

### 4. AWS Deployment

```
Developer → git push → ECR (Docker image) → App Runner (auto-deploy) → Backend running
                                                    ↓
                                          Secrets Manager (API keys)
```

- **ECR**: stores the built Docker image (multi-stage, non-root user,
  healthcheck included).
- **App Runner**: runs the container, handles auto-scaling and the
  HTTPS load balancer. Health checks hit `/v1/health/live`.
- **Secrets Manager** (recommended): injects `GOOGLE_SAFE_BROWSING_API_KEY`,
  `PHISHTANK_API_KEY`, and `EXTENSION_SHARED_SECRET` at runtime.

## Data Flow (Single Page Visit)

1. User navigates to a URL.
2. `webNavigation.onCommitted` fires in the background worker.
3. Local heuristics run synchronously (sub-millisecond) — popup already
   has *something* to show if opened immediately.
4. Background worker POSTs to `/v1/analyze` (rate-limited client-side and
   server-side).
5. Backend re-runs domain/brand analysis authoritatively, queries all
   three threat-intel providers concurrently (cache-first), combines into
   a final verdict.
6. Backend responds with `{verdict, confidence, reasons, triggered_rules,
   ai_score, threat_intel, brand_hits}`.
7. Extension caches the result, updates the toolbar badge, and stores it
   for the popup to render.
8. If the page later submits a password form, `formWatcher.js` checks the
   cached verdict and shows an in-page warning if risky.

## Privacy Boundary

The only data that crosses the extension → backend boundary is: the
**URL being visited**, an optional locally-computed score/flags (for
debugging/telemetry, not trusted), and the extension version. No page
content, form values, or browsing history is ever transmitted or stored
server-side beyond a short-lived (5–15 min) cache entry.

## Resilience Properties

- **Provider down** → circuit breaker opens after 3 failures, short-circuits
  for 60s, other providers + local heuristics continue working.
- **Backend down entirely** → extension falls back to local-only heuristics;
  user still gets a verdict, just without threat-intel enrichment.
- **Rate limit hit** → client receives 429 with `Retry-After`; extension
  already rate-limits itself client-side to avoid hitting this under
  normal use.
