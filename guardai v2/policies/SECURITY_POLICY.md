# GuardAI Security Policy

**Effective Date:** June 20, 2026

## 1. Our Commitment

GuardAI is a security product, and we hold ourselves to a high standard.
We take vulnerability reports seriously and aim to respond promptly to
legitimate security concerns.

## 2. Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x (current beta) | ✅ Yes |
| 0.1.x (legacy MVP)    | ❌ No — please upgrade |

During public beta, only the latest released version receives security
patches.

## 3. Reporting a Vulnerability

If you discover a security vulnerability in GuardAI (extension or
backend), please report it responsibly:

- **Email:** security@guardai.io (placeholder — replace before launch)
- **Do not** open a public GitHub issue for security vulnerabilities.
- **Do not** test vulnerabilities against production infrastructure
  beyond what is necessary to demonstrate the issue (no data
  exfiltration, no denial-of-service testing against production).

### What to Include
- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code/screenshots welcome)
- The affected component (extension, backend API, specific endpoint)
- Your assessment of severity, if you have one

### Our Response Process
1. **Acknowledgment** — within 48 hours of report
2. **Triage & validation** — within 5 business days
3. **Remediation** — timeline depends on severity (see below)
4. **Disclosure coordination** — we'll work with you on responsible
   disclosure timing

| Severity | Target Fix Time |
|----------|-----------------|
| Critical (RCE, auth bypass, mass data exposure) | 72 hours |
| High (privilege escalation, significant data leak) | 7 days |
| Medium (limited data exposure, DoS) | 30 days |
| Low (best-practice gaps, minor info disclosure) | Next release cycle |

## 4. Scope

### In Scope
- GuardAI Chrome extension (all components: background worker, content
  scripts, popup)
- GuardAI backend API (`api.guardai.io` and staging environment)
- GuardAI's Docker/deployment configuration, to the extent it's publicly
  inspectable

### Out of Scope
- Vulnerabilities in third-party services we integrate with (Google Safe
  Browsing, OpenPhish, PhishTank) — please report these to the respective
  vendor
- Social engineering attacks against GuardAI staff
- Physical security of our infrastructure providers (AWS)

## 5. Safe Harbor

We will not pursue legal action against security researchers who:
- Make a good-faith effort to avoid privacy violations, data destruction,
  and service disruption
- Report vulnerabilities promptly and do not publicly disclose before
  remediation
- Do not exploit a vulnerability beyond what's needed to demonstrate it

## 6. Security Practices We Follow

- Least-privilege permissions in the browser extension manifest
- Strict Content Security Policy on all extension pages
- Input validation and sanitization on all backend API endpoints
- Rate limiting and circuit breakers on all external integrations
- No storage of user credentials, page content, or browsing history
- Secrets managed via environment variables / AWS Secrets Manager, never
  hardcoded
- Regular dependency updates and vulnerability scanning (see our
  [Security Audit Report](../docs/SECURITY_AUDIT_REPORT.md))

## 7. Incident Response

In the event of a confirmed security incident affecting users, see our
[Incident Response Policy](./INCIDENT_RESPONSE_POLICY.md) for our
notification and remediation process.
