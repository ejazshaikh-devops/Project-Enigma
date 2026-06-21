# GuardAI — Phase 2 Deliverable Package

This package contains the full Phase 2 upgrade of GuardAI: production-grade
code for the extension and backend, plus all security, legal, and
investor-facing documentation requested.

## What's Inside

```
guardai-phase2/
├── extension/              Chrome MV3 extension (hardened manifest, worker, content scripts, popup)
├── backend/                FastAPI backend (threat intel, brand detection, ML classifier, explainable verdicts)
│   └── ml/                 Logistic regression phishing classifier (see ml/README.md)
├── deploy/                 EC2 + nginx + HTTPS deployment tooling
│   ├── EC2_DEPLOYMENT_GUIDE.md   Full setup guide + honest capacity planning
│   ├── nginx/guardai.conf        Reverse proxy config (HTTP + HTTPS templates)
│   ├── scripts/install_ec2.sh    One-shot installer (nginx, certbot, Docker)
│   └── docker-compose.yml        Single-instance container orchestration
├── docs/
│   ├── ARCHITECTURE.md                    System architecture (text + see interactive diagram in chat)
│   ├── SECURITY_AUDIT_REPORT.md           Full audit: Critical/High/Medium/Low findings + fixes
│   ├── PUBLIC_BETA_CHECKLIST.md           Go/no-go checklist before public launch
│   └── INVESTOR_READINESS_GAP_ANALYSIS.md Honest gap analysis for fundraising
└── policies/
    ├── PRIVACY_POLICY.md
    ├── TERMS_OF_SERVICE.md
    ├── SECURITY_POLICY.md
    └── INCIDENT_RESPONSE_POLICY.md
```

## Quick Start — Backend

```bash
cd backend
cp .env.example .env          # fill in real API keys
pip install -r requirements.txt --break-system-packages
uvicorn main:app --reload --port 8000
```

**Optional but recommended** — download the real pre-trained phishing
model (trained on real data, not synthetic; one command, needs internet):

```bash
pip install -r ml/requirements-download.txt --break-system-packages
python3 -m ml.download_pretrained_model
# restart the backend afterward to pick it up
```

Or with Docker:
```bash
cd backend
docker build -t guardai-backend .
docker run -p 8000:8000 --env-file .env guardai-backend
```

Verify it's running:
```bash
curl http://localhost:8000/v1/health/live
```

## Quick Start — Extension

1. Open `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `extension/` folder
4. Before loading for real testing, update `manifest.json`'s
   `host_permissions` and `background/worker.js`'s `API_ENVIRONMENTS` to
   point at your running backend (e.g. add `http://localhost:8000/*` back
   in for local dev only — **never ship that in a production build**, see
   Security Audit finding C-1)

## Quick Start — Production Deployment on EC2

See `deploy/EC2_DEPLOYMENT_GUIDE.md` for the full walkthrough (nginx +
HTTPS via Let's Encrypt, Docker, capacity planning by instance size). Short
version:

```bash
# On a fresh EC2 instance, after pointing DNS at it:
chmod +x deploy/scripts/install_ec2.sh
./deploy/scripts/install_ec2.sh api.yourdomain.com

cd deploy
cp ../backend/.env.example guardai.env   # fill in real API keys
docker compose up -d
```

No database required — every request is scored live, nothing is
persisted, matching the current product requirements.

## What Changed From the Original MVP

| Area | Before | After (Phase 2) |
|------|--------|------------------|
| Threat intel | None / partial | Google Safe Browsing, OpenPhish, PhishTank, + domain-age via RDAP (catches brand-new scam domains with no brand to impersonate and no blocklist history yet) — concurrent, cached, circuit-broken |
| ML classifier | None — "ai_score" was a relabeled rules score | Two independent models: (1) a real pre-trained model from Hugging Face trained on real labeled data — optional, one download command, see `backend/ml/README.md`; (2) a built-in synthetic-data logistic regression as a fallback. A false-positive bug (flagging real login pages as dangerous) was found and fixed during testing of the synthetic model. |
| Brand detection | Basic | Levenshtein + homoglyph + Unicode normalization, server-side authoritative |
| Verdicts | Simple score | Full explainable verdict: verdict, confidence, reasons, triggered_rules, ai_score |
| Extension permissions | Included a dev `localhost:8000` host permission | Locked to exact production/staging API hosts only |
| CSP | Minimal | Strict `default-src 'none'` with explicit allow-lists |
| Backend auth | None | Rate limiting + CORS lockdown (HMAC signing recommended next, see audit) |
| Input validation | None evident | Strict Pydantic models on every field |
| Docker | Basic | Multi-stage, non-root user, healthcheck |
| Secrets | Unclear | Centralized env-var config, `.env.example`, Secrets Manager recommended |
| Legal docs | None | Privacy Policy, ToS, Security Policy, Incident Response Policy |
| Audit | None | Full Critical/High/Medium/Low security audit |

## Next Steps

See `docs/PUBLIC_BETA_CHECKLIST.md` for the prioritized launch sequence,
and `docs/INVESTOR_READINESS_GAP_ANALYSIS.md` for what to focus on before
fundraising. In short: the engineering foundation is now strong — the
highest-leverage next step is running a real public beta to gather usage
data, not further feature work.
