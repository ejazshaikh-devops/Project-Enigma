# GuardAI — Public Beta Readiness Checklist

Use this as a go/no-go gate before opening GuardAI to public beta users
(Chrome Web Store listing, public sign-ups, etc.)

## Product

- [x] Core phishing detection working (local heuristics + threat intel)
- [x] Brand impersonation detection (typosquatting, homoglyphs, lookalikes)
- [x] Explainable verdicts (verdict, confidence, reasons, triggered_rules)
- [x] Crypto wallet / seed-phrase protection
- [x] Graceful degradation when backend or providers are unavailable
- [x] Lightweight ML classifier trained and integrated (see `backend/ml/README.md`)
- [x] Known ML false-positive class (legitimate login pages) found and fixed
- [ ] Pre-trained model downloaded and verified on the actual deployment
      machine (`python3 -m ml.download_pretrained_model` — could not be
      tested from within the build sandbox, no internet access to
      huggingface.co there; see `backend/ml/README.md`)
- [ ] Domain age (RDAP) provider verified against live traffic on the
      actual deployment machine — could not be tested from within the
      build sandbox, no internet access to rdap.org there; see
      `integrations/domain_age.py` docstring for a verification snippet
- [ ] Tested against a curated set of 50+ known real-world phishing URLs
      (recommend building a small eval set from OpenPhish/PhishTank archives)
- [ ] Tested against 50+ known-legitimate high-traffic sites for false
      positive rate (banks, social media, e-commerce, SaaS login pages)
- [ ] ML model retrained on real (not synthetic) traffic once beta data exists
- [ ] User-facing onboarding flow (first-run experience explaining what
      GuardAI does and doesn't do)

## Security

- [x] Manifest permissions reviewed and minimized
- [x] Strict CSP on extension pages
- [x] Backend input validation (Pydantic, length/type/format limits)
- [x] Rate limiting on backend API
- [x] Circuit breakers on all external threat-intel calls
- [x] No hardcoded secrets in source code
- [x] Non-root Docker user
- [x] Security headers on all API responses
- [ ] HMAC request signing between extension and backend (see Security
      Audit Report, item C-2)
- [ ] External penetration test or security review
- [ ] Dependency vulnerability scan integrated into build process
      (`pip-audit`, `npm audit` equivalent for any JS tooling)

## Infrastructure

- [x] Dockerfile production-hardened (multi-stage, healthcheck, non-root)
- [x] `.env.example` documents all configuration
- [x] nginx + HTTPS reverse proxy config provided (`deploy/nginx/guardai.conf`)
- [x] One-shot EC2 install script provided (`deploy/scripts/install_ec2.sh`)
- [x] `GUNICORN_WORKERS` tunable per instance size without rebuilding image
- [ ] DNS A record pointed at EC2 instance (required before certbot can issue a cert)
- [ ] Production AWS Secrets Manager configured for API keys
- [ ] Redis (ElastiCache) provisioned if running more than 1 instance
- [ ] CloudWatch alarms configured for error rate, latency, and health check failures
- [ ] Centralized error monitoring (Sentry or equivalent) wired up
- [ ] Production Google Safe Browsing API key obtained (with appropriate
      quota for expected beta traffic)
- [ ] PhishTank application key obtained (free tier rate limits are too
      low for real usage)
- [ ] Staging environment fully mirrors production configuration for
      pre-release testing

## Legal & Compliance

- [x] Privacy Policy drafted
- [x] Terms of Service drafted
- [x] Security Policy / responsible disclosure process drafted
- [x] Incident Response Policy drafted
- [ ] Legal review of all policy documents by a licensed attorney
- [ ] GDPR/CCPA applicability assessment if EU/California users expected
- [ ] Real contact emails configured (privacy@, legal@, security@) —
      currently placeholders in policy docs

## Chrome Web Store Submission

- [ ] Store listing copy written (description, screenshots, promotional
      images)
- [ ] Privacy practices disclosure completed in Chrome Web Store Developer
      Dashboard (must match actual data practices — see Privacy Policy)
- [ ] Extension icon set finalized (16/48/128px, already present)
- [ ] `GUARDAI_EXTENSION_ID` set in backend CORS config once the Web Store
      assigns the extension's permanent ID
- [ ] Beta vs. stable channel strategy decided (Chrome Web Store supports
      trusted tester / unlisted distribution for controlled beta rollout)

## Observability & Support

- [ ] Status page or equivalent uptime communication channel
- [ ] Support/feedback channel for beta users (email, form, or Discord)
- [ ] Telemetry dashboard built on top of `/v1/metrics` for tracking
      adoption, verdict distribution, and threat-block counts
- [ ] Defined process for triaging user-reported false positives/negatives

## Recommended Launch Sequence

1. Close out remaining Security Audit action items (HMAC signing, Secrets
   Manager migration)
2. Run the extension against the phishing/legitimate test sets above and
   tune thresholds if false-positive rate is too high
3. Soft-launch to a small trusted-tester group via Chrome Web Store's
   unlisted distribution
4. Monitor `/v1/metrics` and CloudWatch for a 1–2 week burn-in period
5. Address any issues found, then open to public beta
6. Begin investor conversations with real (anonymized) beta usage data —
   significantly strengthens the pitch (see Investor Readiness Gap
   Analysis)
