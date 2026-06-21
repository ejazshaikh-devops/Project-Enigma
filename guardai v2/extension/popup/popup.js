/**
 * GuardAI – popup.js  v0.2.0
 * Displays explainable AI verdicts: verdict, confidence, reasons, triggered_rules,
 * ai_score, and threat_intel from the backend.
 * No imports — CSP requires script-src 'self'.
 */

(function () {
  'use strict';

  var VERSION = chrome.runtime.getManifest().version;
  document.getElementById('ext-version').textContent = 'v' + VERSION;

  // ── Label maps ──────────────────────────────────────────────────────────────

  var RULE_LABELS = {
    'no_https':                  'No HTTPS encryption',
    'ip_address_host':           'IP address used as domain',
    'known_phishing_domain':     'Known phishing domain',
    'excessive_subdomains':      'Suspicious subdomain chain',
    'suspicious_tld':            'High-risk domain extension',
    'excessive_hyphens':         'Too many hyphens in domain',
    'unicode_homograph':         'Fake look-alike characters (homoglyph)',
    'long_url':                  'Unusually long URL',
    'malformed_url':             'Malformed URL',
    'login_path':                'Login or verification path',
    'at_symbol_in_url':          'Hidden destination trick (@)',
    'encoded_redirect':          'Redirect pattern in URL',
    'many_query_params':         'Too many URL parameters',
    'page_external_form_action': 'Form submits data to another domain',
    'page_payment_fields':       'Payment fields detected',
    'page_login_form':           'Login form detected',
    'page_suspicious_language':  'Urgent / threatening language on page',
    'page_many_forms':           'Unusually high number of forms',
  };

  function labelRule(rule) {
    if (RULE_LABELS[rule]) return RULE_LABELS[rule];
    if (rule.indexOf('brand_impersonation:') === 0) {
      var parts = rule.split(':');
      return '"' + parts[1] + '" brand impersonation (' + (parts[2] || '') + ')';
    }
    if (rule.indexOf('phishing_keywords:') === 0) {
      return rule.split(':')[1] + ' phishing keywords found';
    }
    if (rule.indexOf('threat_intel:') === 0) {
      return 'Flagged by ' + rule.split(':')[1];
    }
    return rule;
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  function showResult(url, riskData) {
    var score      = typeof riskData.score === 'number' ? riskData.score : (riskData.confidence / 100 || 0);
    score          = Math.max(0, Math.min(1, score));
    var confidence = riskData.confidence != null ? riskData.confidence : Math.round(score * 100);
    var verdict    = riskData.verdict || (score >= 0.85 ? 'dangerous' : score >= 0.5 ? 'suspicious' : 'safe');
    var reasons    = Array.isArray(riskData.reasons) ? riskData.reasons : [];
    var rules      = Array.isArray(riskData.triggered_rules) ? riskData.triggered_rules : [];
    var tiHits     = Array.isArray(riskData.threat_intel) ? riskData.threat_intel : [];
    var aiScore    = riskData.ai_score != null ? riskData.ai_score : null;
    var source     = riskData.source || 'local';
    var pct        = Math.round(score * 100);

    // Card
    var card  = document.getElementById('card');
    var icon  = document.getElementById('icon');
    var title = document.getElementById('title');
    var sub   = document.getElementById('sub');
    var conf  = document.getElementById('confidence-line');

    card.className = 'card ' + verdict;

    if (verdict === 'dangerous') {
      icon.textContent  = '🛑';
      title.textContent = 'Dangerous page';
      sub.textContent   = 'Do NOT enter passwords or payment details';
    } else if (verdict === 'suspicious') {
      icon.textContent  = '⚠️';
      title.textContent = 'Suspicious page';
      sub.textContent   = 'Proceed with caution — verify before entering data';
    } else {
      icon.textContent  = '✓';
      title.textContent = 'Page looks safe';
      sub.textContent   = 'No significant threats detected';
    }

    var confParts = ['Confidence: ' + confidence + '%'];
    if (aiScore !== null) confParts.push('AI score: ' + aiScore + '/100');
    conf.textContent = confParts.join(' · ');

    // Risk bar
    var scoreWrap = document.getElementById('score-wrap');
    var scorePct  = document.getElementById('score-pct');
    var fill      = document.getElementById('fill');
    var sourceVal = document.getElementById('source-val');
    scoreWrap.classList.remove('hide');
    scorePct.textContent  = pct + ' / 100';
    fill.style.width      = pct + '%';
    sourceVal.textContent = ({ local: 'Local heuristics', api: 'AI + Threat Intelligence', cache: 'Cached result', page: 'Page analysis' })[source] || source;

    // URL
    document.getElementById('url-val').textContent = url || '—';

    // Threat intel
    var tiWrap = document.getElementById('ti-wrap');
    var tiList = document.getElementById('ti-list');
    tiList.innerHTML = '';
    if (tiHits.length > 0) {
      tiWrap.classList.remove('hide');
      tiHits.forEach(function (hit) {
        var li = document.createElement('li');
        li.textContent = hit.source + ': ' + (hit.threat || 'Known threat');
        tiList.appendChild(li);
      });
    } else {
      tiWrap.classList.add('hide');
    }

    // Reasons
    var rWrap = document.getElementById('reasons-wrap');
    var rList = document.getElementById('reasons-list');
    rList.innerHTML = '';
    if (verdict !== 'safe' && reasons.length > 0) {
      rWrap.classList.remove('hide');
      rList.className = 'reasons-list';
      reasons.slice(0, 5).forEach(function (r) {
        var li = document.createElement('li');
        li.textContent = r;
        rList.appendChild(li);
      });
    } else if (verdict === 'safe') {
      rWrap.classList.remove('hide');
      rList.className = 'reasons-list safe';
      var li = document.createElement('li');
      li.textContent = 'Domain passed all security checks';
      rList.appendChild(li);
    } else {
      rWrap.classList.add('hide');
    }

    // Triggered rules (collapsed by default if no threat)
    var fWrap = document.getElementById('flags-wrap');
    var fList = document.getElementById('flags-list');
    fList.innerHTML = '';
    var relevantRules = rules.filter(function (r) {
      return r !== 'login_path'; // too noisy for safe sites
    });
    if (verdict !== 'safe' && relevantRules.length > 0) {
      fWrap.classList.remove('hide');
      relevantRules.slice(0, 8).forEach(function (rule) {
        var li = document.createElement('li');
        li.textContent = labelRule(rule);
        fList.appendChild(li);
      });
    } else {
      fWrap.classList.add('hide');
    }
  }

  function showError(msg, detail) {
    document.getElementById('icon').textContent  = '—';
    document.getElementById('title').textContent = msg || 'Cannot scan this page';
    document.getElementById('sub').textContent   = detail || '';
  }

  function samePage(a, b) {
    try {
      var ua = new URL(a); ua.hash = '';
      var ub = new URL(b); ub.hash = '';
      return ua.href === ub.href;
    } catch (e) { return a === b; }
  }

  // ── Boot ─────────────────────────────────────────────────────────────────────

  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (!tabs || tabs.length === 0) { showError('No active tab'); return; }

    var url = tabs[0].url || '';
    document.getElementById('url-val').textContent = url || '—';

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      showError('Not a web page', 'GuardAI only scans http/https pages');
      return;
    }

    // Request stored verdict from background
    chrome.runtime.sendMessage({ type: 'GET_TAB_RISK' }, function (riskData) {
      if (chrome.runtime.lastError || !riskData || !samePage(riskData.url, url)) {
        // Fallback: show a basic local scan indicator
        showResult(url, { score: 0, verdict: 'safe', confidence: 0, reasons: ['Waiting for scan result…'], triggered_rules: [], source: 'local' });
        return;
      }
      showResult(url, riskData);
    });
  });

})();
