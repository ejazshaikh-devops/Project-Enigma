# GuardAI Privacy Policy

**Effective Date:** June 20, 2026
**Last Updated:** June 20, 2026

## 1. Overview

GuardAI ("we", "our", "the Extension") is a browser extension that protects
users from phishing, brand impersonation, scam pages, and malicious
redirects. This Privacy Policy explains what data GuardAI collects, why,
and how it is handled. We built GuardAI on a **privacy-first** principle:
we do not collect or store your browsing history.

## 2. What We Collect

### 2.1 Data Sent for Threat Analysis
When you visit a webpage, GuardAI sends the **page URL** to our backend API
to be checked against threat intelligence feeds (Google Safe Browsing,
OpenPhish, PhishTank) and analyzed for phishing indicators. This is
necessary for the extension's core function.

- URLs are analyzed in real time and are **not stored** linked to your
  identity, IP address, or any persistent user ID.
- We do not maintain a history of which sites you visited.

### 2.2 Page Signals (Local Analysis)
GuardAI's content script inspects the structure of a page (presence of
password fields, payment fields, external form submission targets, and
counts of certain warning phrases) to improve detection accuracy. **We do
not collect or transmit the text content of pages, form values, passwords,
or any data you type.** Only boolean/numeric signals (e.g.,
"has_password_field: true") are used, and these are processed to compute a
risk score — they are not stored as identifiable telemetry.

### 2.3 Aggregate, Anonymous Telemetry
We collect anonymous, aggregate usage statistics to improve the product:

- Total number of scans performed
- Number of threats blocked
- Distribution of verdicts (safe / suspicious / dangerous)
- Extension version in use
- API response latency

This telemetry **cannot be tied to an individual user**, contains no URLs,
no IP addresses, and no browsing history.

### 2.4 What We Do NOT Collect
- Your browsing history
- Page content, form inputs, passwords, or payment details
- Cookies or persistent tracking identifiers
- Personally identifiable information (name, email, address) unless you
  voluntarily provide it (e.g., contacting support)

## 3. How We Use Data

- To determine whether a page is safe, suspicious, or dangerous
- To improve our detection models and threat intelligence accuracy
- To monitor system health and performance (aggregate metrics only)

We do **not** sell, rent, or share your data with advertisers or data
brokers.

## 4. Third-Party Threat Intelligence Services

To check URLs against known threats, GuardAI queries:
- **Google Safe Browsing API** (Google LLC)
- **OpenPhish** feed
- **PhishTank** community database

When GuardAI queries these services, the URL you are visiting is shared
with them in the same way it would be if you used Google Chrome's built-in
Safe Browsing feature. Please refer to each provider's own privacy policy
for how they handle this data:
- Google Safe Browsing: https://policies.google.com/privacy
- PhishTank: https://www.phishtank.com/privacy.php

## 5. Data Retention

- URLs submitted for analysis are cached for a short period (typically 5–15
  minutes) purely to improve performance and avoid redundant lookups, then
  discarded.
- Aggregate telemetry counters are retained indefinitely in anonymized,
  non-identifiable form for product analytics.

## 6. Data Security

We apply industry-standard safeguards including encrypted transport
(HTTPS/TLS) for all communications between the extension and our backend,
rate limiting, and access controls on our infrastructure. See our
[Security Policy](./SECURITY_POLICY.md) for details.

## 7. Your Choices

- You can disable or uninstall GuardAI at any time via your browser's
  extension settings.
- You can switch between API environments (Production/Staging) in the
  extension popup if participating in beta testing.

## 8. Children's Privacy

GuardAI is not directed at children under 13, and we do not knowingly
collect data from children.

## 9. Changes to This Policy

We may update this Privacy Policy as GuardAI evolves. Material changes
will be reflected in the extension's release notes and this document's
"Last Updated" date.

## 10. Contact Us

For privacy questions or concerns, contact: **privacy@guardai.io**
(placeholder — update with your real support address before public launch)

---
*This policy is provided as a starting template for GuardAI's public beta
launch. We recommend a legal review before publishing, particularly
regarding GDPR/CCPA applicability if you have EU or California users.*
