# GuardAI — EC2 Deployment Guide (No Database, Live-Only)

This documents the exact setup for running GuardAI on a single EC2
instance with nginx + HTTPS in front of your Docker container, with no
database — every request is scored live and nothing is persisted. This
matches your current architecture and is sufficient for public beta.

## Architecture for This Setup

```
Chrome Extension (user's browser)
        │  HTTPS
        ▼
nginx (port 443) ── terminates TLS, rate-limits at the edge
        │  proxy_pass to 127.0.0.1:8000
        ▼
Docker container: gunicorn + uvicorn workers running GuardAI FastAPI app
        │
        ├─→ Google Safe Browsing (live HTTPS call)
        ├─→ OpenPhish feed (polled + cached in-memory)
        └─→ PhishTank (live HTTPS call)

No database. No persistent storage. In-memory cache + rate limiter only.
Container restart = clean slate (this is intentional for your current stage).
```

## Step 1 — Provision / Prepare the EC2 Instance

- **Recommended size for early beta:** `t3.small` (2 vCPU, 2GB RAM). This
  comfortably handles a few hundred concurrent extension users. See the
  capacity table below before picking a size.
- **Security Group inbound rules:** allow port 22 (SSH, ideally restricted
  to your IP), port 80 (HTTP, needed for certbot's initial handshake), and
  port 443 (HTTPS).
- **DNS:** point an A record (e.g. `api.guardai.io`) at the instance's
  Elastic IP. Certbot cannot issue a cert for a bare IP address — you need
  a real domain, even a cheap one.

## Step 2 — Run the Install Script

```bash
chmod +x deploy/scripts/install_ec2.sh
./deploy/scripts/install_ec2.sh api.guardai.io
```

This installs nginx, certbot, and Docker; sets up an initial HTTP proxy
config; and runs certbot to obtain and install a free Let's Encrypt
certificate, auto-configuring nginx for HTTPS and auto-renewal.

After it completes, **manually apply the GuardAI-specific hardening**
(rate limiting, body size caps, blocking non-API paths) using the
commented HTTPS template in `deploy/nginx/guardai.conf` — copy those
settings into `/etc/nginx/sites-available/guardai` (certbot will have
already added the `listen 443 ssl` block; you're adding the extra
directives inside it), then:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## Step 3 — Run the Backend Container

```bash
cd deploy
cp ../backend/.env.example guardai.env
nano guardai.env   # fill in GOOGLE_SAFE_BROWSING_API_KEY, etc.

# Option A: build locally on the instance
docker compose build
docker compose up -d

# Option B: pull from your ECR repo instead
IMAGE_URI=<account-id>.dkr.ecr.<region>.amazonaws.com/guardai-backend:latest \
  docker compose up -d
```

Note `guardai.env` should set `GUARDAI_ENV=production` and
`GUARDAI_ALLOWED_ORIGINS=chrome-extension://<your-published-extension-id>`
once you have a real Chrome Web Store listing ID. Until then, leave it
empty during testing — but **set it before public launch**, otherwise any
website's JavaScript could call your API directly.

## Step 4 — Verify

```bash
curl https://api.guardai.io/v1/health/live
# {"status":"ok"}

curl -X POST https://api.guardai.io/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"http://paypa1-login-verify.tk/secure"}'
# Should return a "dangerous" verdict with reasons
```

## Step 5 — Point the Extension at It

In `extension/manifest.json`, set `host_permissions` and the CSP
`connect-src` to your real domain (already templated for
`https://api.guardai.io` — just confirm it matches your actual domain).

In `extension/background/worker.js`, confirm `API_ENVIRONMENTS.production.endpoint`
points at `https://api.guardai.io/v1/analyze`.

Reload the unpacked extension in `chrome://extensions`, visit a test
phishing-style URL, and confirm the popup shows a live verdict.

---

## Capacity Planning — What Actually Happens Under Load

Honest numbers, not marketing numbers. These assume the no-DB,
in-memory-cache architecture you have now.

| Instance | RAM | Recommended `GUNICORN_WORKERS` | Realistic concurrent active users | Sustained req/s before degradation |
|---|---|---|---|---|
| t3.micro | 1GB | 1 | ~50–150 | ~20–40 |
| t3.small | 2GB | 2 (default) | ~300–600 | ~60–100 |
| t3.medium | 4GB | 3–4 | ~800–1500 | ~150–250 |

**Why "active users" is much higher than "requests per second":** a
single browsing user doesn't hammer the API — they trigger one `/v1/analyze`
call roughly every 10–30 seconds as they navigate. So a server doing
60 req/s can plausibly support several hundred simultaneously browsing
users, not 60.

**What actually causes a crash (in order of likelihood):**
1. **OOM from too many gunicorn workers for the instance's RAM.** Each
   worker is a full Python process (~150–250MB depending on libraries
   loaded). 4 workers on a 1GB instance will get OOM-killed under load.
   This is why `GUNICORN_WORKERS` is now a tunable env var — match it to
   your instance size using the table above.
2. **Threat-intel provider throttling**, not your own server. PhishTank's
   free tier rate-limits aggressively; Google Safe Browsing has a daily
   quota. Your circuit breakers already handle this gracefully (they open
   and the system falls back to local heuristics) — but it means your
   *effective* capacity may be limited by a third party, not your EC2
   instance, until you get production API keys.
3. **A traffic spike with no edge protection.** This is what the nginx
   `limit_req`/`limit_conn` directives in `deploy/nginx/guardai.conf`
   exist to prevent — they shed excess load at the nginx layer before it
   ever reaches gunicorn, so the container degrades by returning 429s
   instead of falling over.

**What does NOT crash it:** normal Chrome Web Store adoption growth (tens
to low hundreds of installs over weeks) on a t3.small. You'd need a sudden
spike — a viral moment, or someone deliberately hammering the API — to hit
real trouble, and the nginx rate limiting plus your existing circuit
breakers are exactly the mitigations for that.

**When to actually worry / upgrade:**
- Health check / container restarts showing up in `docker logs guardai-backend`
- `docker stats` consistently showing memory near the `mem_limit` ceiling
- 429 responses in nginx access logs becoming common during normal (not
  attack) traffic

At that point, the fix is either (a) bump to `t3.medium` and increase
`GUNICORN_WORKERS`, or (b) move to the AWS App Runner setup you'd already
started configuring, which auto-scales. Both are drop-in — nothing in the
application code needs to change, since there's no database to migrate.

## Monitoring Without a Database

Since `/v1/metrics` only holds in-memory counters that reset on restart,
for anything beyond quick spot-checks, rely on:
- `docker stats guardai-backend` — live CPU/memory
- `docker logs -f guardai-backend` — gunicorn access/error logs
- AWS CloudWatch agent on the instance (optional, free tier covers basic
  CPU/memory/disk metrics) for historical graphs without needing a DB
