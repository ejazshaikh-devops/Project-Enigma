/**
 * GuardAI – Content Script: formWatcher.js  v0.2.0
 * Intercepts form submissions on suspicious pages and warns the user.
 * Extra protection for crypto wallet seed phrase fields.
 */

(function () {
  'use strict';

  if (window.__guardai_formwatcher_loaded) return;
  window.__guardai_formwatcher_loaded = true;

  var pendingSubmit = null;
  var RISK_WARN     = 0.5;
  var RISK_BLOCK    = 0.85;

  // ── Warning Banner ──────────────────────────────────────────────────────────

  function showBanner(score, onContinue) {
    var existing = document.getElementById('guardai-warning');
    if (existing) existing.remove();

    var isDangerous = score >= RISK_BLOCK;
    var banner      = document.createElement('div');
    banner.id       = 'guardai-warning';
    banner.setAttribute('role', 'alert');
    banner.setAttribute('aria-live', 'assertive');

    Object.assign(banner.style, {
      position:   'fixed',
      top:        '0',
      left:       '0',
      width:      '100%',
      background: isDangerous ? '#7F1D1D' : '#78350F',
      color:      '#FEF2F2',
      fontFamily: '-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
      fontSize:   '14px',
      fontWeight: '500',
      padding:    '14px 20px',
      zIndex:     '2147483647',
      boxSizing:  'border-box',
      display:    'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap:        '16px',
      boxShadow:  '0 4px 24px rgba(0,0,0,0.4)',
      borderBottom: isDangerous ? '2px solid #EF4444' : '2px solid #F59E0B',
    });

    var msg = isDangerous
      ? '🛑 GuardAI: This site is flagged as DANGEROUS. Do NOT submit your password or payment details.'
      : '⚠️ GuardAI: This site looks suspicious. Verify you trust it before submitting any data.';

    var text = document.createElement('span');
    text.textContent = msg;
    text.style.cssText = 'flex:1;line-height:1.5';

    var btnRow = document.createElement('div');
    btnRow.style.cssText = 'display:flex;gap:8px;flex-shrink:0';

    var btnContinue = document.createElement('button');
    btnContinue.textContent = 'Submit anyway';
    Object.assign(btnContinue.style, {
      background:   '#FEF2F2',
      border:       '1px solid rgba(255,255,255,0.7)',
      color:        isDangerous ? '#7F1D1D' : '#78350F',
      cursor:       'pointer',
      padding:      '6px 14px',
      borderRadius: '5px',
      fontSize:     '12px',
      fontWeight:   '700',
    });
    btnContinue.onclick = function () {
      if (!window.confirm('GuardAI Security Warning\n\nThis site may be unsafe. Are you sure you want to submit?\n\nOnly continue if you are certain this is a legitimate site.')) return;
      banner.remove();
      if (pendingSubmit && pendingSubmit.form) {
        continueSubmit(pendingSubmit.form, pendingSubmit.submitter);
      }
      pendingSubmit = null;
      onContinue && onContinue();
    };

    var btnDismiss = document.createElement('button');
    btnDismiss.textContent = 'Cancel';
    Object.assign(btnDismiss.style, {
      background:   'rgba(255,255,255,0.15)',
      border:       '1px solid rgba(255,255,255,0.3)',
      color:        '#FEF2F2',
      cursor:       'pointer',
      padding:      '6px 14px',
      borderRadius: '5px',
      fontSize:     '12px',
    });
    btnDismiss.onclick = function () {
      banner.remove();
      pendingSubmit = null;
    };

    btnRow.appendChild(btnContinue);
    btnRow.appendChild(btnDismiss);
    banner.appendChild(text);
    banner.appendChild(btnRow);
    document.documentElement.prepend(banner);

    // Auto-dismiss after 30 seconds on warn (not on danger)
    if (!isDangerous) {
      setTimeout(function () {
        if (document.getElementById('guardai-warning') === banner) banner.remove();
      }, 30000);
    }
  }

  // ── Crypto Wallet Protection ─────────────────────────────────────────────────

  function isSeedPhraseField(input) {
    var name = (input.name + ' ' + input.id + ' ' + input.placeholder).toLowerCase();
    return name.indexOf('seed') !== -1 ||
           name.indexOf('mnemonic') !== -1 ||
           name.indexOf('secret phrase') !== -1 ||
           name.indexOf('recovery phrase') !== -1 ||
           name.indexOf('private key') !== -1;
  }

  function protectSeedPhraseFields() {
    var inputs = document.querySelectorAll('input[type="text"], input[type="password"], textarea');
    inputs.forEach(function (input) {
      if (input.dataset.guardaiSeedProtected) return;
      if (!isSeedPhraseField(input)) return;
      input.dataset.guardaiSeedProtected = '1';

      input.addEventListener('focus', function () {
        var notice = document.getElementById('guardai-seed-notice');
        if (notice) return;
        var el = document.createElement('div');
        el.id = 'guardai-seed-notice';
        el.setAttribute('role', 'alert');
        Object.assign(el.style, {
          position:    'fixed',
          bottom:      '16px',
          right:       '16px',
          background:  '#1E293B',
          border:      '1px solid #EF4444',
          color:       '#FCA5A5',
          fontFamily:  '-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
          fontSize:    '13px',
          padding:     '12px 16px',
          borderRadius:'8px',
          zIndex:      '2147483647',
          maxWidth:    '300px',
          lineHeight:  '1.5',
          boxShadow:   '0 4px 24px rgba(0,0,0,0.5)',
        });
        el.textContent = '🛡️ GuardAI: Never enter your seed phrase or private key on a website. Legitimate services never ask for this.';
        document.body.appendChild(el);
        setTimeout(function () { el.remove(); }, 8000);
      });
    });
  }

  // ── Form Submit Interception ─────────────────────────────────────────────────

  function watchForms() {
    document.addEventListener('submit', function (event) {
      var form = event.target;
      // Only intercept forms with password fields
      if (!form.querySelector('input[type="password"]')) return;
      // If we already approved this submit, let it through
      if (form.dataset.guardaiAllowSubmit === '1') {
        delete form.dataset.guardaiAllowSubmit;
        return;
      }

      event.preventDefault();
      event.stopImmediatePropagation();

      var submitter = event.submitter || null;
      pendingSubmit = { form: form, submitter: submitter };

      chrome.runtime.sendMessage({ type: 'GET_TAB_RISK' }, function (riskData) {
        if (chrome.runtime.lastError || !riskData) {
          // Background unavailable — allow submission
          pendingSubmit = null;
          continueSubmit(form, submitter);
          return;
        }
        var score = typeof riskData.score === 'number' ? riskData.score : 0;
        if (score >= RISK_WARN) {
          showBanner(score, null);
        } else {
          pendingSubmit = null;
          continueSubmit(form, submitter);
        }
      });
    }, true);
  }

  function continueSubmit(form, submitter) {
    form.dataset.guardaiAllowSubmit = '1';
    try {
      if (typeof form.requestSubmit === 'function') {
        form.requestSubmit(submitter || undefined);
      } else {
        form.submit();
      }
    } catch (e) {
      form.submit();
    }
  }

  // ── Init ─────────────────────────────────────────────────────────────────────

  watchForms();

  // Protect seed phrase fields — run now and again after dynamic content loads
  protectSeedPhraseFields();
  setTimeout(protectSeedPhraseFields, 2000);

})();
