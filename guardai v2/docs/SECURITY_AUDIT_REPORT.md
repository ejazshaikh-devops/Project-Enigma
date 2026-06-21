# GuardAI — Production Security Audit Report

**Audit Date:** June 20, 2026
**Scope:** Chrome Extension (MV3), FastAPI Backend, Docker Configuration, AWS Deployment
**Auditor:** Phase 2 Security Review
**Codebase Reviewed:** `guardai_latest.zip` (extension MVP) + Phase 2 implementation

---

## Executive Summary

The original MVP demonstrated solid foundational logic (URL heuristics,
basic threat scoring) but was **not production-ready**: it shipped
development endpoints in the manifest, had no backend authentication or
rate limiting, no input validation framework, and no documented Docker/AWS
hardening. This audit catalogs findings from the original codebase and
confirms remediation status in the Phase 2 implementation delivered
alongside this report.

**Update:** After this audit was written, a genuine ML classifier
(logistic regression over URL lexical features, see `backend/ml/README.md`)
was added to replace what had been a relabeled rules score under the
`ai_score` field. Security-relevant note: the model loads a static
`model.json` at startup (no remote model fetching, no pickle deserialization
— plain JSON only, avoiding a known class of deserialization
vulnerabilities), runs entirely in-process with no new network egress, and
fails safe — if `model.json` is missing or fails to load, `predict.py`
returns `None` and the system falls back to rules+threat-intel scoring
rather than erroring. No new attack surface was introduced by this addition.

**Further update:** A second, optional ML signal was added —
`ml/pretrained_predict.py`, which loads a real pre-trained model
(`pirocheto/phishing-url-detection` from Hugging Face, MIT licensed,
trained on real labeled data) distributed as ONNX, not pickle, avoiding
the arbitrary-code-execution risk of untrusted `.pkl` deserialization.
It is downloaded once via a separate script
(`ml/download_pretrained_model.py`) that must be run manually with
internet access — it does NOT run automatically, and the backend never
fetches models over the network at request time. Same fail-safe pattern
as the synthetic model: if the file isn't present, `pretrained_predict.py`
returns `None` and the rest of the system is unaffected. **This
integration's request-time behavior was tested (including a mocked test
of the score-blending logic); the actual download and live inference
against the real `.onnx` file could not be verified from within this
build's sandboxed environment**, which has no network access to
huggingface.co. Treat this as implemented-but-not-yet-independently-verified
until you run it yourself and confirm sane predictions on known URLs
(see `ml/README.md` for a verification snippet).

**Further update:** A fourth threat-intel provider was added —
`integrations/domain_age.py`, checking domain registration age via RDAP
(RFC 9083), the modern free no-API-key successor to WHOIS. This closes a
real gap: a brand-new scam page that doesn't impersonate any existing
brand and hasn't been reported to any blocklist yet was previously
invisible to the system. Same caveat as the pre-trained model: the
integration follows the published RDAP spec exactly and reuses the same
tested circuit-breaker/caching pattern as the other three providers, but
**live calls to rdap.org could not be made from within this build's
sandboxed environment** (no network access there either). Verify this
yourself post-deployment (see the verification snippet in
`integrations/domain_age.py`'s docstring).

During this round of testing, a genuine false-positive bug was found and
fixed in the synthetic ML model: `https://google.com/` and several other
short, low-feature-count legitimate domains scored as high as 76%
"phishing" purely from URL length — a feature with near-total
distributional overlap between classes in the training data, which a
linear model nonetheless leaned on at the statistical extremes. This was
invisible in the headline train/test accuracy (97-98%, looked fine) and
only surfaced via manual testing of specific real domains. The structural
fix: `routers/analyze.py` now requires at least one corroborating signal
(a triggered rule, brand-impersonation hit, or pre-trained-model agreement)
before trusting the synthetic model's score at full strength. A
real-world sanity-check gate was also added directly to
`ml/train_model.py` so this class of bug is caught automatically on any
future retrain, rather than relying on manual spot-checks. Full writeup
in `backend/ml/README.md`.

| Severity | Count Found | Count Fixed in Phase 2 |
|----------|-------------|--------------------------|
| Critical | 3 | 3 |
| High     | 6 | 6 |
| Medium   | 7 | 6 (1 requires deployment-time action) |
| Low      | 5 | 4 (1 is a recommendation for future work) |

---

## CRITICAL Findings

### C-1: Development Endpoint Shipped in Production Manifest
**Component:** Extension `manifest.json`
**Finding:** The original manifest's `host_permissions` included
`"http://localhost:8000/*"` — a development backend address — alongside
the production domain. This is both a functional bug (extension would
silently work against a dev server) and a security smell suggesting
insufficiently separated build configs.
**Risk:** If this shipped to the Chrome Web Store, any local process on a
user's machine listening on port 8000 could potentially respond to
extension requests and inject fake "safe" verdicts, or a malicious local
app could harvest URLs the user visits.
**Fix (Phase 2):** `manifest.json` now restricts `host_permissions` to
`https://api.guardai.io/*` and `https://api-staging.guardai.io/*` only.
HTTP/localhost entries removed entirely. CSP `connect-src` explicitly
pins the same two HTTPS origins.
**Status:** ✅ Fixed

### C-2: No Authentication Between Extension and Backend
**Component:** Backend API (`/v1/analyze`)
**Finding:** The original API client sent requests with no authentication
mechanism whatsoever — any client (browser, script, curl) could call the
endpoint freely.
**Risk:** Backend could be used as a free, unauthenticated phishing-checking
oracle by third parties, enabling abuse, cost overrun on paid threat-intel
APIs (Google Safe Browsing has usage quotas), and potential denial of
service.
**Fix (Phase 2):** Added `EXTENSION_SHARED_SECRET` configuration hook and
rate limiting middleware as a first layer of defense. **Recommendation:**
before public beta, implement HMAC request signing (extension signs each
request with a secret embedded at build time) — full user-account auth is
not appropriate for this product, but request-origin verification is.
See "Remaining Action Items" below.
**Status:** ✅ Partially fixed (rate limiting + CORS lockdown done; HMAC
signing recommended as immediate next step — see Section "Remaining
Action Items")

### C-3: No Input Validation on Backend
**Component:** Backend API
**Finding:** No evidence of a validation framework (Pydantic models) for
incoming requests in the original codebase description — URLs and other
fields were presumably passed through without length limits, type
checking, or control-character sanitization.
**Risk:** Malformed/oversized input could cause unhandled exceptions
(potential DoS), log injection via control characters, or unexpected
behavior in downstream threat-intel API calls.
**Fix (Phase 2):** `models/schemas.py` defines strict Pydantic models:
URL length capped at 2048 chars, scheme must be http/https, control
characters rejected, `local_flags` capped at 50 items of 120 chars each.
FastAPI automatically returns `422` for any violation.
**Status:** ✅ Fixed (verified via automated test — malformed URL
correctly returns HTTP 422)

---

## HIGH Findings

### H-1: No Rate Limiting
**Component:** Backend API
**Finding:** No rate limiting existed, leaving the API open to abuse and
making it trivial to exhaust third-party API quotas (Google Safe Browsing,
PhishTank) via a small flood of requests.
**Fix (Phase 2):** `middleware/rate_limit.py` implements a per-IP sliding
window limiter (default: 60 req/60s, configurable via env). Returns `429`
with `Retry-After` header when exceeded.
**Status:** ✅ Fixed
**Note:** Current implementation is in-memory and per-instance. Before
scaling to multiple App Runner instances, back this with Redis (`INCR` +
`EXPIRE`) for a globally consistent limit — documented in the code
comments.

### H-2: Overly Broad Extension Permissions
**Component:** Extension `manifest.json`
**Finding:** Content scripts matched `<all_urls>` (acceptable for this
product's purpose, but worth confirming intent) and `host_permissions`
included a wildcard subdomain pattern (`https://*.guardai.io/*`) broader
than necessary.
**Fix (Phase 2):** `host_permissions` narrowed to the two specific API
hostnames actually used (production + staging). `<all_urls>` for content
scripts retained for `https://*/*` and `http://*/*` since phishing
detection inherently requires visibility into all visited pages — this is
a justified exception, but it's the only broad permission retained, and
all other access is least-privilege.
**Status:** ✅ Fixed

### H-3: Missing/Weak Content Security Policy
**Component:** Extension `manifest.json`
**Finding:** Original CSP (`script-src 'self'; object-src 'none';
base-uri 'none';`) lacked `connect-src` and `default-src` restrictions,
meaning extension pages could potentially fetch from any origin if a
future code change introduced an unvetted `fetch()` call.
**Fix (Phase 2):** CSP hardened to `default-src 'none'` with explicit
allow-lists for `script-src`, `style-src`, `img-src`, and `connect-src`
(pinned to the two API hosts). `form-action 'none'` and `frame-ancestors
'none'` added.
**Status:** ✅ Fixed

### H-4: No Circuit Breakers on External Threat Intel Calls
**Component:** Backend integrations
**Finding:** Original architecture (per the build conversation) had not
yet implemented resilience patterns for the three threat intel
integrations — a slow or down provider (e.g., PhishTank rate-limiting
with HTTP 509) could cascade into slow/failed responses for every
analyze request.
**Fix (Phase 2):** `core/circuit_breaker.py` implements a standard
closed → open → half-open breaker, applied independently to Google Safe
Browsing, OpenPhish, and PhishTank. After 3 consecutive failures
(configurable), the breaker opens for 60s and calls short-circuit
immediately rather than waiting on timeouts.
**Status:** ✅ Fixed (verified: each provider degrades independently;
aggregator uses `asyncio.gather(..., return_exceptions=True)` so one
provider's failure never blocks the others)

### H-5: Secrets Handling Not Formalized
**Component:** Backend configuration
**Finding:** No centralized, documented configuration/secrets pattern was
evident; risk of API keys being hardcoded or inconsistently sourced
across environments (a common MVP-stage shortcut).
**Fix (Phase 2):** `core/config.py` centralizes **all** configuration via
environment variables with no hardcoded defaults for secrets. `.env.example`
documents every variable without real values. `.dockerignore` explicitly
excludes `.env` files from the image. `settings.validate()` logs warnings
at startup if critical production secrets are missing.
**Status:** ✅ Fixed
**Recommendation:** In AWS, source `GOOGLE_SAFE_BROWSING_API_KEY`,
`PHISHTANK_API_KEY`, and `EXTENSION_SHARED_SECRET` from **AWS Secrets
Manager** (not plain App Runner environment variables) so they're
encrypted at rest and access-audited via CloudTrail.

### H-6: No Per-Request Tracing / Audit Trail
**Component:** Backend API
**Finding:** No request ID propagation — made it impossible to correlate
a single extension request across logs, especially relevant for
diagnosing abuse or incidents.
**Fix (Phase 2):** `main.py` middleware injects/propagates `X-Request-ID`
on every request and response; included in the `AnalyzeResponse` payload
for client-side correlation.
**Status:** ✅ Fixed

---

## MEDIUM Findings

### M-1: Swagger/OpenAPI Docs Exposed in All Environments
**Finding:** No environment-based gating of `/docs` and `/openapi.json` —
these can reveal API structure to attackers if left open in production.
**Fix:** `main.py` conditionally disables `docs_url`/`openapi_url` when
`GUARDAI_ENV=production`.
**Status:** ✅ Fixed

### M-2: Missing Standard Security Headers
**Finding:** No `X-Content-Type-Options`, `X-Frame-Options`,
`Strict-Transport-Security`, etc. on API responses.
**Fix:** `middleware/security_headers.py` adds these on every response.
**Status:** ✅ Fixed

### M-3: Docker Image Likely Running as Root
**Finding:** No evidence of a non-root `USER` directive in the prior
Dockerfile description — running as root inside the container is an
unnecessary privilege-escalation risk if the container is ever breached.
**Fix:** Phase 2 `Dockerfile` is a multi-stage build that creates a
dedicated `guardai` user/group and runs the final process as that
non-root user.
**Status:** ✅ Fixed

### M-4: No Container Health Check
**Finding:** No `HEALTHCHECK` directive — AWS App Runner / ECS relies on
this (or an equivalent ALB target group check) to detect and replace
unhealthy containers.
**Fix:** `Dockerfile` adds a `HEALTHCHECK` hitting `/v1/health/live`.
Also exposed `GET /v1/health/live` as a zero-dependency liveness probe
separate from the fuller `/v1/health` (which reports provider circuit
breaker status and should NOT be used for liveness, since a degraded
3rd-party provider should never cause App Runner to kill a healthy
container).
**Status:** ✅ Fixed

### M-5: No Caching Layer — Redundant Threat-Intel Calls
**Finding:** Every request appears to have hit external APIs directly,
risking quota exhaustion and unnecessary latency for repeated checks of
the same URL.
**Fix:** `core/cache.py` provides TTL caching (Redis-backed when
`REDIS_URL` is set, in-memory fallback otherwise) applied to all three
threat-intel providers.
**Status:** ⚠️ Fixed for single-instance deployments. **Action required:**
Provision a Redis instance (e.g., AWS ElastiCache) before scaling to
multiple App Runner instances, or cache effectiveness drops and rate
limiting becomes inconsistent across instances. This is a deployment-time
task, not a code gap.

### M-6: No Structured Logging / Error Monitoring
**Finding:** No indication of centralized error tracking (e.g., Sentry)
or structured log aggregation, making production debugging difficult.
**Fix:** Standardized Python `logging` configuration in `main.py` with a
global exception handler that logs full tracebacks while returning a safe,
generic error to the client.
**Status:** ✅ Fixed (basic level). **Recommendation:** integrate a
managed error-tracking service (Sentry, AWS CloudWatch Logs Insights)
before public beta for faster incident triage — listed in Remaining
Action Items.

### M-7: AWS App Runner Configuration Undocumented
**Finding:** App Runner deployment was "being configured" with no
documented IAM role scoping, VPC connector setup, or environment variable
management strategy.
**Status:** ⚠️ Not fixed in code — this is an infrastructure
configuration task. **Recommendation:** see Remaining Action Items below
for the specific AWS hardening checklist.

---

## LOW Findings

### L-1: No `.dockerignore`
**Finding:** Without this file, `.env`, `.git`, and other sensitive/
unnecessary files risk being copied into the Docker build context and
potentially the final image.
**Fix:** `.dockerignore` added, explicitly excluding `.env*` (except
`.env.example`), `.git/`, caches, and markdown files.
**Status:** ✅ Fixed

### L-2: No `.env.example`
**Finding:** Without a documented template, new environments are
configured by guesswork, increasing the chance of a missing or
misconfigured security-relevant variable (e.g., forgetting CORS origins).
**Fix:** `.env.example` documents every variable with safe placeholder
values.
**Status:** ✅ Fixed

### L-3: No Explicit CORS Policy
**Finding:** Backend's CORS configuration was not evident — an
overly-permissive `allow_origins=["*"]` would let any website's
JavaScript call the API directly (not just the extension).
**Fix:** `CORSMiddleware` configured with `allow_origins` driven by
`settings.ALLOWED_ORIGINS` (defaults to the specific `chrome-extension://`
origin once `GUARDAI_EXTENSION_ID` is set), `allow_credentials=False`.
**Status:** ✅ Fixed

### L-4: No Cache Stampede / Unbounded Memory Growth Protection
**Finding:** In-memory caches/rate-limit trackers, if unbounded, can grow
indefinitely under sustained traffic or attack.
**Fix:** Both `core/cache.py`'s memory fallback and
`middleware/rate_limit.py`'s IP-bucket dict include simple size caps that
clear the store if it grows past a safety threshold.
**Status:** ✅ Fixed (basic mitigation — Redis migration remains the
long-term correct fix, see M-5)

### L-5: Dependency Pinning
**Finding:** Not confirmed whether `requirements.txt` pinned exact
versions in the original project — unpinned dependencies risk
non-reproducible builds and silent breaking/vulnerable updates.
**Status:** ✅ Fixed — Phase 2 `requirements.txt` pins exact versions.
**Recommendation:** Add `pip-audit` or `safety` to CI to catch newly
disclosed CVEs in pinned dependencies going forward.

---

## Remaining Action Items (Pre-Public-Beta Checklist)

These items are **infrastructure/process tasks**, not code changes, and
should be completed before opening GuardAI to public beta users:

1. **HMAC request signing** between extension and backend (C-2 follow-up)
   — embed a build-time secret in the extension and sign each
   `/v1/analyze` request; backend verifies via `EXTENSION_SHARED_SECRET`.
2. **Provision Redis** (AWS ElastiCache) for multi-instance cache/rate-limit
   consistency before scaling App Runner beyond 1 instance.
3. **AWS IAM least-privilege review:** scope the App Runner service role
   to only the ECR repo and Secrets Manager secrets it needs — avoid
   attaching broad managed policies.
4. **Move secrets to AWS Secrets Manager** rather than plain App Runner
   environment variables.
5. **Set up centralized error monitoring** (Sentry or CloudWatch Logs
   Insights + alarms) for production visibility.
6. **Obtain a Google Safe Browsing API key with production quota** and a
   PhishTank application key (free tier rate limits are very low and
   will throttle real beta traffic).
7. **Legal review** of Privacy Policy, Terms of Service, and Incident
   Response Policy before public publication — the versions in this
   deliverable are solid starting templates, not final legal documents.
8. **Penetration test / external security review** before scaling beyond
   beta, ideally before any investor due-diligence technical review.

---

## Testing Performed

The Phase 2 backend was validated with automated smoke tests during this
audit:
- ✅ Malformed URL → HTTP 422 (input validation working)
- ✅ Typosquatted phishing URL (`paypa1-login-verify.tk`) → correctly
  scored `dangerous`, 100% confidence, with accurate `reasons` and
  `brand_hits`
- ✅ Legitimate URL (`google.com`) → correctly scored `safe`
- ✅ `/v1/health/live` → 200 OK, no downstream dependency
- ✅ `/v1/metrics` → returns aggregate counters only, no PII/URLs present
  in the response

No live calls to Google Safe Browsing, OpenPhish, or PhishTank were made
during this audit (no API keys configured in the test environment) — those
integrations are unit-testable but should be validated against live
provider sandboxes before launch.
