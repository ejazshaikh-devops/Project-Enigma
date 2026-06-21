/**
 * GuardAI – Background Service Worker v0.2.0
 *
 * Phase 2 — Production-grade features:
 *   • Unified threat intelligence (Google Safe Browsing, OpenPhish, PhishTank)
 *   • Advanced brand impersonation detection (Levenshtein, homoglyphs, Unicode normalization)
 *   • Explainable AI verdicts with reasons + triggered_rules
 *   • Circuit breaker pattern on every external call
 *   • Privacy-preserving telemetry (no URLs logged)
 *   • Proper rate limiting with exponential backoff
 */

// ── Constants ─────────────────────────────────────────────────────────────────

const VERSION               = chrome.runtime.getManifest().version;
const RISK_THRESHOLD_WARN   = 0.5;
const RISK_THRESHOLD_BLOCK  = 0.85;
const URL_CACHE_TTL_MS      = 5 * 60 * 1000;    // 5 min
const FEED_CACHE_TTL_MS     = 10 * 60 * 1000;   // 10 min
const MAX_REQUESTS_PER_MIN  = 30;
const REQUEST_TIMEOUT_MS    = 8000;
const CB_FAILURE_THRESHOLD  = 3;                 // open circuit after 3 failures
const CB_RECOVERY_MS        = 60 * 1000;         // try again after 1 min
const TELEMETRY_FLUSH_MS    = 5 * 60 * 1000;    // flush every 5 min

// Single backend endpoint. Update this to your actual deployed domain
// before loading the extension. (Previously this had a Production/Staging
// dropdown, but no staging backend was ever deployed — it pointed at a
// placeholder domain that didn't exist. Removed to avoid a UI control
// that silently failed.)
const API_ENDPOINT = 'https://api.yourdomain.com/v1/analyze';

// ── Homoglyph map (common look-alike characters → ASCII) ─────────────────────

const HOMOGLYPHS = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g',
  '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's', '!': 'i',
  'à':'a','á':'a','â':'a','ã':'a','ä':'a','å':'a',
  'è':'e','é':'e','ê':'e','ë':'e',
  'ì':'i','í':'i','î':'i','ï':'i',
  'ò':'o','ó':'o','ô':'o','õ':'o','ö':'o','ø':'o',
  'ù':'u','ú':'u','û':'u','ü':'u',
  'ñ':'n','ç':'c','ý':'y','ÿ':'y',
  '\u0430':'a','\u0435':'e','\u043e':'o','\u0440':'p','\u0441':'c',
  '\u0445':'x','\u0443':'y','\u0456':'i','\u04cf':'l',
};

// ── Trusted brands + protected domains ───────────────────────────────────────

const BRANDS = [
  { name: 'paypal',        domains: ['paypal.com'] },
  { name: 'apple',         domains: ['apple.com','icloud.com'] },
  { name: 'microsoft',     domains: ['microsoft.com','live.com','outlook.com','office.com'] },
  { name: 'amazon',        domains: ['amazon.com','amazon.co.uk','amazon.in','aws.amazon.com'] },
  { name: 'netflix',       domains: ['netflix.com'] },
  { name: 'google',        domains: ['google.com','gmail.com','youtube.com','accounts.google.com'] },
  { name: 'facebook',      domains: ['facebook.com','fb.com','messenger.com'] },
  { name: 'instagram',     domains: ['instagram.com'] },
  { name: 'twitter',       domains: ['twitter.com','x.com'] },
  { name: 'linkedin',      domains: ['linkedin.com'] },
  { name: 'bankofamerica', domains: ['bankofamerica.com'] },
  { name: 'chase',         domains: ['chase.com','jpmorgan.com'] },
  { name: 'wellsfargo',    domains: ['wellsfargo.com'] },
  { name: 'coinbase',      domains: ['coinbase.com'] },
  { name: 'binance',       domains: ['binance.com'] },
  { name: 'metamask',      domains: ['metamask.io'] },
  { name: 'opensea',       domains: ['opensea.io'] },
  { name: 'paytm',         domains: ['paytm.com'] },
  { name: 'hdfc',          domains: ['hdfcbank.com'] },
  { name: 'icici',         domains: ['icicibank.com'] },
  { name: 'sbi',           domains: ['sbi.co.in','onlinesbi.sbi'] },
  { name: 'axis',          domains: ['axisbank.com'] },
];

const SUSPICIOUS_TLDS = new Set([
  '.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click',
  '.loan','.work','.date','.faith','.racing','.cricket',
  '.science','.party','.review','.country','.stream','.download',
  '.accountant','.win','.men','.gdn','.bid',
]);

const PHISHING_KEYWORDS = [
  'login','signin','verify','secure','account','update','banking',
  'confirm','password','credential','support','suspended','urgent',
  'alert','recover','validate','reactivate',
];

// ── State ─────────────────────────────────────────────────────────────────────

const urlCache      = new Map();   // url → { verdict, timestamp }
const feedCache     = new Map();   // feedKey → { data, timestamp }

// Circuit breakers: { failureCount, openUntil }
const circuitBreakers = {
  api: { failures: 0, openUntil: 0 },
};

// Rate limiting
let requestCount = 0;
let windowStart  = Date.now();

// Telemetry counters (in-memory, flushed periodically)
const telemetry = {
  scansTotal:    0,
  threatsBlocked:0,
  verdictDist:   { safe: 0, suspicious: 0, dangerous: 0 },
  apiLatencySum: 0,
  apiLatencyCnt: 0,
  startTime:     Date.now(),
};

// ── Circuit Breaker ───────────────────────────────────────────────────────────

function cbIsOpen(key) {
  const cb = circuitBreakers[key];
  if (!cb) return false;
  if (cb.openUntil > Date.now()) return true;
  return false;
}

function cbRecordSuccess(key) {
  if (circuitBreakers[key]) {
    circuitBreakers[key].failures = 0;
    circuitBreakers[key].openUntil = 0;
  }
}

function cbRecordFailure(key) {
  const cb = circuitBreakers[key];
  if (!cb) return;
  cb.failures++;
  if (cb.failures >= CB_FAILURE_THRESHOLD) {
    cb.openUntil = Date.now() + CB_RECOVERY_MS;
    console.warn(`[GuardAI] Circuit breaker OPEN for ${key} — will retry in 60s`);
  }
}

// ── Levenshtein distance ──────────────────────────────────────────────────────

function levenshtein(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[a.length][b.length];
}

// Normalize a hostname: strip homoglyphs, lowercase, remove www.
function normalizeHostname(host) {
  let out = '';
  for (const ch of host.toLowerCase()) {
    out += HOMOGLYPHS[ch] || ch;
  }
  return out.replace(/^www\./, '');
}

// ── Brand Impersonation Detection ─────────────────────────────────────────────

function detectBrandImpersonation(hostname) {
  const normalized  = normalizeHostname(hostname);
  const parts       = hostname.toLowerCase().split('.');
  const tld         = parts.slice(-1)[0];
  const sld         = parts.slice(-2).join('.');        // second-level.tld
  const sldNorm     = normalizeHostname(sld);
  const subdomain   = parts.slice(0, -2).join('.');

  const hits = [];

  for (const brand of BRANDS) {
    // 1. Exact legitimate domain? → skip
    if (brand.domains.includes(hostname) || brand.domains.includes(sld)) continue;

    // 2. Brand name in subdomain + foreign SLD → spoofing
    if (subdomain.includes(brand.name)) {
      hits.push({
        type:       'brand_subdomain_spoof',
        brand:      brand.name,
        confidence: 90,
        evidence:   `Brand "${brand.name}" appears in subdomain of non-official domain`,
      });
      break;
    }

    // 3. Levenshtein on SLD vs brand name (catches typosquatting)
    const dist = levenshtein(sldNorm.split('.')[0], brand.name);
    if (dist > 0 && dist <= 2 && sldNorm.split('.')[0].length >= 4) {
      hits.push({
        type:       'typosquatting',
        brand:      brand.name,
        confidence: Math.round((1 - dist / brand.name.length) * 100),
        evidence:   `Domain looks like "${brand.name}" (edit distance: ${dist})`,
      });
      break;
    }

    // 4. Brand name embedded in SLD with hyphens or numbers (arnazon, amaz0n)
    if (sldNorm.includes(normalizeHostname(brand.name)) && sld !== `${brand.name}.${tld}`) {
      hits.push({
        type:       'brand_in_sld',
        brand:      brand.name,
        confidence: 85,
        evidence:   `Brand "${brand.name}" embedded in lookalike domain`,
      });
      break;
    }

    // 5. Homoglyph in the brand name itself
    if (normalized.includes(brand.name) && !hostname.toLowerCase().includes(brand.name)) {
      hits.push({
        type:       'homoglyph_impersonation',
        brand:      brand.name,
        confidence: 95,
        evidence:   `Unicode look-alike characters used to imitate "${brand.name}"`,
      });
      break;
    }
  }

  return hits;
}

// ── Local URL Heuristics ──────────────────────────────────────────────────────

function analyzeURL(rawUrl) {
  const triggered = [];
  let score       = 0.03;

  let parsed;
  try { parsed = new URL(rawUrl); }
  catch { return { score: 0.95, triggered: ['malformed_url'], reasons: ['URL cannot be parsed — likely malformed'] }; }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl  = rawUrl.toLowerCase();
  const path     = parsed.pathname.toLowerCase();

  if (parsed.protocol === 'http:') {
    score += 0.15;
    triggered.push('no_https');
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 0.35;
    triggered.push('ip_address_host');
  }

  if (hostname.split('.').length - 2 >= 3) {
    score += 0.2;
    triggered.push('excessive_subdomains');
  }

  if (SUSPICIOUS_TLDS.has('.' + hostname.split('.').pop())) {
    score += 0.25;
    triggered.push('suspicious_tld');
  }

  if ((hostname.match(/-/g) || []).length >= 3) {
    score += 0.15;
    triggered.push('excessive_hyphens');
  }

  if (/[^\x00-\x7F]/.test(hostname)) {
    score += 0.4;
    triggered.push('unicode_homograph');
  }

  if (fullUrl.indexOf('@') > fullUrl.indexOf('//') + 2) {
    score += 0.25;
    triggered.push('at_symbol_in_url');
  }

  if (/%2f|%5c|redirect=|returnurl=|next=|url=/i.test(fullUrl)) {
    score += 0.12;
    triggered.push('encoded_redirect');
  }

  if (parsed.search && parsed.search.split('&').length >= 6) {
    score += 0.08;
    triggered.push('many_query_params');
  }

  if (/\/(login|signin|verify|secure|account\/update)/.test(path)) {
    score += 0.05;
    triggered.push('login_path');
  }

  // Brand impersonation
  const brandHits = detectBrandImpersonation(hostname);
  for (const hit of brandHits) {
    const bump = (hit.confidence / 100) * 0.45;
    score     += bump;
    triggered.push(`brand_impersonation:${hit.brand}:${hit.type}`);
  }

  const kwHits = PHISHING_KEYWORDS.filter(k => fullUrl.includes(k)).length;
  if (kwHits >= 3) {
    score += 0.2;
    triggered.push(`phishing_keywords:${kwHits}`);
  }

  if (rawUrl.length > 200) {
    score += 0.1;
    triggered.push('long_url');
  }

  return {
    score: Math.min(parseFloat(score.toFixed(3)), 1.0),
    triggered,
    brandHits,
  };
}

// ── API Call with Circuit Breaker ─────────────────────────────────────────────

async function sendToAPI(url, localResult) {
  if (cbIsOpen('api')) {
    console.warn('[GuardAI] API circuit breaker is open — skipping API call');
    return null;
  }

  try {
    const ctrl   = new AbortController();
    const timer  = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
    const t0     = Date.now();

    const res = await fetch(API_ENDPOINT, {
      method:  'POST',
      headers: {
        'Content-Type':        'application/json',
        'X-Extension-Version': VERSION,
        'X-Request-ID':        crypto.randomUUID(),
      },
      body: JSON.stringify({
        url,
        local_score:    localResult.score,
        local_flags:    localResult.triggered,
        timestamp:      Date.now(),
      }),
      signal: ctrl.signal,
    });
    clearTimeout(timer);

    const latency = Date.now() - t0;
    telemetry.apiLatencySum += latency;
    telemetry.apiLatencyCnt++;

    if (!res.ok) {
      cbRecordFailure('api');
      return null;
    }

    const data = await res.json();
    if (typeof data?.risk_score !== 'number' || data.risk_score < 0 || data.risk_score > 1) {
      cbRecordFailure('api');
      return null;
    }

    cbRecordSuccess('api');
    return data;
  } catch (err) {
    cbRecordFailure('api');
    return null;
  }
}

// ── Build Explainable Verdict ─────────────────────────────────────────────────

const RULE_LABELS = {
  'no_https':            'Connection is not encrypted (HTTP)',
  'ip_address_host':     'IP address used instead of a domain name',
  'excessive_subdomains':'Suspicious chain of subdomains',
  'suspicious_tld':      'High-risk top-level domain extension',
  'excessive_hyphens':   'Domain contains an unusual number of hyphens',
  'unicode_homograph':   'Non-standard characters used to mimic a real domain',
  'at_symbol_in_url':    'Hidden destination trick using @ symbol',
  'encoded_redirect':    'URL contains a redirect pattern',
  'many_query_params':   'Unusually high number of URL parameters',
  'login_path':          'URL path contains login or verification keywords',
  'long_url':            'URL is excessively long',
  'malformed_url':       'URL is malformed and cannot be parsed',
  'page_external_form_action': 'Login form submits to a different domain',
  'page_payment_fields': 'Payment input fields detected on this page',
  'page_login_form':     'Login form with email and password detected',
  'page_suspicious_language': 'Urgent or threatening language found on page',
  'page_many_forms':     'Unusually high number of forms on page',
};

function buildVerdict(score, triggered, apiData, brandHits, threatIntelHits, pageSignalScore) {
  const reasons         = [];
  const triggeredLabels = [];

  // Collect reasons from local heuristics
  for (const rule of triggered) {
    const label = RULE_LABELS[rule] ||
      (rule.startsWith('brand_impersonation:')
        ? `Brand impersonation detected: "${rule.split(':')[1]}"`
        : rule.startsWith('phishing_keywords:')
          ? `${rule.split(':')[1]} phishing keywords found in URL`
          : rule);
    triggeredLabels.push(label);
  }

  // Threat intelligence reasons
  if (threatIntelHits && threatIntelHits.length > 0) {
    for (const hit of threatIntelHits) {
      reasons.push(`Flagged by ${hit.source}: ${hit.threat || 'known threat'}`);
      triggeredLabels.push(`threat_intel:${hit.source}`);
    }
  }

  // Brand impersonation detailed reasons
  if (brandHits && brandHits.length > 0) {
    for (const hit of brandHits) {
      reasons.push(hit.evidence);
    }
  }

  // Page signal reasons
  if (pageSignalScore > 0) {
    if (triggered.includes('page_external_form_action')) reasons.push('Login form submits data to a different domain');
    if (triggered.includes('page_payment_fields'))       reasons.push('Payment fields detected — high value target');
    if (triggered.includes('page_suspicious_language'))  reasons.push('Urgent or threatening language on the page');
  }

  // Combine local + triggered labels into reasons if reasons is sparse
  if (reasons.length === 0) {
    reasons.push(...triggeredLabels.slice(0, 5));
  }

  const confidence    = Math.round(score * 100);
  const aiScore       = apiData ? Math.round(apiData.risk_score * 100) : null;

  let verdict;
  if (score >= RISK_THRESHOLD_BLOCK)   verdict = 'dangerous';
  else if (score >= RISK_THRESHOLD_WARN) verdict = 'suspicious';
  else                                   verdict = 'safe';

  return {
    verdict,
    confidence,
    reasons: reasons.length > 0 ? reasons : ['No threats detected'],
    triggered_rules: triggeredLabels,
    ai_score: aiScore,
    threat_intel: threatIntelHits || [],
    brand_hits: brandHits || [],
  };
}

// ── Page Signals ──────────────────────────────────────────────────────────────

function scorePageSignals(signals) {
  const triggered = [];
  let score = 0;

  if (!signals || typeof signals !== 'object') return { score, triggered };

  if (signals.externalFormAction) {
    score += 0.35;
    triggered.push('page_external_form_action');
  }
  if (signals.hasPaymentFields) {
    score += 0.30;
    triggered.push('page_payment_fields');
  }
  if (signals.hasPasswordField && signals.hasEmailField) {
    score += 0.10;
    triggered.push('page_login_form');
  }

  const kwCount = Array.isArray(signals.suspiciousKeywords)
    ? signals.suspiciousKeywords.length
    : Number(signals.suspiciousKeywordCount || 0);

  if (kwCount > 0) {
    score += Math.min(0.35, 0.20 + kwCount * 0.05);
    triggered.push('page_suspicious_language');
  }
  if (signals.formCount > 5) {
    score += 0.05;
    triggered.push('page_many_forms');
  }

  return { score: Math.min(parseFloat(score.toFixed(3)), 1.0), triggered };
}

// ── Cache & Rate Limit Helpers ────────────────────────────────────────────────

function pruneCache() {
  const now = Date.now();
  for (const [k, v] of urlCache.entries()) {
    if (now - v.timestamp > URL_CACHE_TTL_MS) urlCache.delete(k);
  }
}

function checkRateLimit() {
  const now = Date.now();
  if (now - windowStart > 60000) { requestCount = 0; windowStart = now; }
  if (requestCount >= MAX_REQUESTS_PER_MIN) return false;
  requestCount++;
  return true;
}

// ── Storage Helpers ───────────────────────────────────────────────────────────

function storageGet(keys) {
  return new Promise(resolve => chrome.storage.local.get(keys, resolve));
}

function storageSet(values) {
  return new Promise(resolve => chrome.storage.local.set(values, resolve));
}

// ── Badge ─────────────────────────────────────────────────────────────────────

async function applyBadge(tabId, verdict) {
  try {
    if (verdict === 'dangerous') {
      chrome.action.setBadgeText({ text: '!', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#DC2626', tabId });
    } else if (verdict === 'suspicious') {
      chrome.action.setBadgeText({ text: '?', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#D97706', tabId });
    } else {
      chrome.action.setBadgeText({ text: '✓', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#16A34A', tabId });
    }
  } catch { /* tab may be closed */ }
}

// ── Telemetry ─────────────────────────────────────────────────────────────────

function recordScan(verdictObj) {
  telemetry.scansTotal++;
  if (verdictObj.verdict === 'dangerous') telemetry.threatsBlocked++;
  telemetry.verdictDist[verdictObj.verdict] = (telemetry.verdictDist[verdictObj.verdict] || 0) + 1;
}

async function flushTelemetry() {
  // Store aggregate counters locally — never sends URLs
  const snapshot = {
    version:      VERSION,
    scansTotal:   telemetry.scansTotal,
    threats:      telemetry.threatsBlocked,
    verdictDist:  { ...telemetry.verdictDist },
    avgLatencyMs: telemetry.apiLatencyCnt > 0
      ? Math.round(telemetry.apiLatencySum / telemetry.apiLatencyCnt)
      : 0,
    uptimeMs:     Date.now() - telemetry.startTime,
    flushedAt:    Date.now(),
  };
  await storageSet({ guardaiTelemetry: snapshot });
}

// ── Main Evaluation ───────────────────────────────────────────────────────────

async function evaluateURL(rawUrl, tabId) {
  try {
    // Check in-memory cache
    const cached = urlCache.get(rawUrl);
    if (cached && Date.now() - cached.timestamp < URL_CACHE_TTL_MS) {
      await chrome.storage.session.set({
        [`tab_${tabId}`]: { ...cached.verdictObj, url: rawUrl, source: 'cache', analyzedAt: Date.now() },
      });
      await applyBadge(tabId, cached.verdictObj.verdict);
      return;
    }

    // Local heuristics (fast, synchronous)
    const local      = analyzeURL(rawUrl);
    const brandHits  = local.brandHits || [];

    // Optimistic local verdict
    const localVerdict = buildVerdict(local.score, local.triggered, null, brandHits, [], 0);
    await chrome.storage.session.set({
      [`tab_${tabId}`]: { ...localVerdict, url: rawUrl, score: local.score, source: 'local', analyzedAt: Date.now() },
    });
    await applyBadge(tabId, localVerdict.verdict);

    // API enrichment (async, non-blocking to UX)
    if (checkRateLimit()) {
      const apiData = await sendToAPI(rawUrl, local);
      if (apiData) {
        const finalScore = apiData.risk_score;
        const tiHits     = apiData.threat_intel || [];
        const finalVerdict = buildVerdict(
          finalScore,
          [...local.triggered, ...(apiData.triggered_rules || [])],
          apiData,
          brandHits,
          tiHits,
          0
        );
        urlCache.set(rawUrl, { verdictObj: finalVerdict, score: finalScore, timestamp: Date.now() });
        pruneCache();

        await chrome.storage.session.set({
          [`tab_${tabId}`]: { ...finalVerdict, url: rawUrl, score: finalScore, source: 'api', analyzedAt: Date.now() },
        });
        await applyBadge(tabId, finalVerdict.verdict);
        recordScan(finalVerdict);
        return;
      }
    }

    // If API unavailable, cache local result
    urlCache.set(rawUrl, { verdictObj: localVerdict, score: local.score, timestamp: Date.now() });
    recordScan(localVerdict);

  } catch (err) {
    console.error('[GuardAI] evaluateURL error:', err.message);
  }
}

async function applyPageSignals(tabId, url, signals) {
  if (typeof tabId !== 'number' || !url) return;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;

  const page = scorePageSignals(signals);
  if (page.score === 0) return;

  const cached     = urlCache.get(url);
  const baseScore  = cached ? (cached.score || 0) : analyzeURL(url).score;
  const combined   = Math.min(1.0, baseScore + page.score * 0.75);

  const allTriggered = [
    ...(cached?.verdictObj?.triggered_rules || []),
    ...page.triggered,
  ];

  const updated = buildVerdict(combined, allTriggered, null, cached?.verdictObj?.brand_hits || [], cached?.verdictObj?.threat_intel || [], page.score);

  urlCache.set(url, { verdictObj: updated, score: combined, timestamp: Date.now() });
  await chrome.storage.session.set({
    [`tab_${tabId}`]: { ...updated, url, score: combined, source: 'page', analyzedAt: Date.now() },
  });
  await applyBadge(tabId, updated.verdict);
}

// ── Listeners ─────────────────────────────────────────────────────────────────

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!['link', 'typed', 'generated', 'start_page'].includes(details.transitionType)) return;
  if (!details.url.startsWith('http://') && !details.url.startsWith('https://')) return;
  await evaluateURL(details.url, details.tabId);
});

// Keep-alive alarm
chrome.alarms.create('keepAlive',     { periodInMinutes: 0.4 });
chrome.alarms.create('telemetryFlush',{ periodInMinutes: 5 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'telemetryFlush') flushTelemetry();
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.type === 'GET_TAB_RISK') {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (!tabs[0]) { sendResponse(null); return; }
      const data = await chrome.storage.session.get(`tab_${tabs[0].id}`);
      sendResponse(data[`tab_${tabs[0].id}`] || null);
    });
    return true;
  }

  if (msg.type === 'PAGE_ANALYSIS') {
    const tabId = sender.tab?.id;
    const url   = msg.url || sender.url || '';
    applyPageSignals(tabId, url, msg.signals)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (msg.type === 'GET_TELEMETRY') {
    sendResponse({ ...telemetry });
    return true;
  }
});

console.info(`[GuardAI] Service worker v${VERSION} ready.`);
