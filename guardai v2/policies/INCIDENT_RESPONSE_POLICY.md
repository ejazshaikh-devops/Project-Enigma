# GuardAI Incident Response Policy

**Effective Date:** June 20, 2026

## 1. Purpose

This policy defines how GuardAI detects, responds to, and recovers from
security incidents affecting the extension, backend API, or user data —
ensuring a fast, coordinated, and transparent response.

## 2. Incident Severity Classification

| Level | Definition | Examples |
|-------|------------|----------|
| **SEV-1 (Critical)** | Active exploitation, data breach, or service compromise affecting users | Backend RCE, leaked API keys actively abused, malicious extension update pushed |
| **SEV-2 (High)** | Significant vulnerability or partial outage with real but contained risk | Auth bypass discovered (not yet exploited), sustained API outage |
| **SEV-3 (Medium)** | Limited-impact issue, degraded functionality | One threat-intel provider down, elevated false-positive rate |
| **SEV-4 (Low)** | Minor issue, no immediate user risk | Non-exploitable bug, documentation gap |

## 3. Roles & Responsibilities

| Role | Responsibility |
|------|-----------------|
| **Incident Commander (IC)** | Owns the response, makes go/no-go decisions, coordinates communication |
| **Technical Lead** | Diagnoses root cause, implements/validates the fix |
| **Communications Lead** | Drafts and sends user/public notifications |

*(For a solo-founder/small-team stage, one person may hold multiple roles —
this structure should scale as the team grows.)*

## 4. Response Process

### Step 1 — Detection
Incidents may be identified via:
- Internal monitoring/alerting (error rates, circuit breaker trips, AWS
  CloudWatch alarms)
- Security researcher reports (see Security Policy)
- User reports
- Threat intelligence provider notifications

### Step 2 — Triage (Target: within 1 hour for SEV-1/2)
- Confirm the incident is real (not a false alarm)
- Assign severity level
- Designate Incident Commander

### Step 3 — Containment
- **Backend compromise:** Rotate affected secrets/API keys immediately via
  AWS Secrets Manager; restrict/disable the affected endpoint if needed
- **Malicious/compromised extension release:** Pull the release from the
  Chrome Web Store; if actively harmful, publish a security advisory
  instructing users to disable the extension
- **Threat intel provider compromise/outage:** Circuit breakers should
  already isolate this automatically; confirm graceful degradation is
  working

### Step 4 — Eradication & Recovery
- Patch the root cause
- Verify the fix in staging before production deployment
- Deploy fix to production
- Confirm monitoring shows normal behavior restored

### Step 5 — User Notification
For SEV-1 incidents involving user data exposure:
- Notify affected users within **72 hours** of confirmation (aligned with
  GDPR breach notification expectations, even if not yet formally
  applicable)
- Publish a public incident summary once details are confirmed
- Notification will include: what happened, what data was involved (if
  any), what we did about it, and what users should do

### Step 6 — Post-Incident Review
Within 5 business days of resolution:
- Document timeline, root cause, and impact
- Identify process/technical gaps that allowed the incident
- Create action items to prevent recurrence
- Update this policy and the Security Audit Report if systemic gaps are
  found

## 5. Communication Channels

- **Internal:** (define your team's incident channel — e.g., dedicated
  Slack channel)
- **External:** status page (to be established before GA), email to
  registered beta users, extension update notes

## 6. Specific Incident Playbooks

### API Key / Secret Leak
1. Immediately rotate the affected key in AWS Secrets Manager / provider
   dashboard (Google Cloud Console for Safe Browsing key, etc.)
2. Audit access logs for unauthorized usage during the exposure window
3. Redeploy backend with the new secret
4. Review how the leak occurred (git history, logs, etc.) and remediate

### Malicious Extension Update Detected
1. Immediately unpublish/pull the version from the Chrome Web Store
2. Determine scope: was this a compromised release pipeline or a
   supply-chain issue (compromised dependency)?
3. Publish guidance for users to disable/remove the extension if needed
4. Conduct full review of the build & release process before re-publishing

### Backend Outage
1. Check AWS App Runner / ECR / health check status
2. Confirm whether it's an infrastructure issue or application bug
3. Extension should degrade gracefully to local-only detection (no API
   dependency for core heuristics) — verify this is functioning
4. Roll back to last known-good deployment if a recent release caused it

### Threat Intelligence Provider Failure
This should be handled automatically by circuit breakers; verify:
1. Circuit breaker opened correctly for the failing provider
2. Other providers + local heuristics continue functioning
3. No user-facing errors — degraded mode only

## 7. Review Cadence

This policy should be reviewed and updated quarterly, or after any SEV-1/2
incident, whichever comes first.
