/**
 * GuardAI – Content Script: detector.js  v0.2.0
 * Runs at document_idle. Analyzes page DOM for phishing signals and sends
 * aggregated signals (NO page text, NO PII) to the background worker.
 */

(function () {
  'use strict';

  if (window.__guardai_detector_loaded) return;
  window.__guardai_detector_loaded = true;

  var SUSPICIOUS_PHRASES = [
    'verify your account',
    'account suspended',
    'urgent action required',
    'confirm your identity',
    'your account will be closed',
    'update your payment',
    'bank verification required',
    'login to continue',
    'verify your email',
    'your account has been limited',
    'unusual sign-in activity',
    'your wallet has been compromised',
    'connect your wallet',
    'claim your reward',
    'you have been selected',
    'act immediately',
    'account will be deactivated',
    'security alert',
  ];

  function analyzePageContent() {
    var signals = {
      hasPasswordField:     false,
      hasEmailField:        false,
      hasPaymentFields:     false,
      hasCryptoFields:      false,
      suspiciousKeywords:   [],
      formCount:            0,
      externalFormAction:   false,
      hiddenPasswordFields: 0,
      iframeCount:          document.querySelectorAll('iframe').length,
      externalScriptCount:  0,
    };

    // Input field analysis
    var inputs = document.querySelectorAll('input');
    inputs.forEach(function (input) {
      var type = (input.type || '').toLowerCase();
      var name = (input.name || input.id || input.placeholder || '').toLowerCase();

      if (type === 'password') {
        signals.hasPasswordField = true;
        if (input.style.display === 'none' || input.hidden) signals.hiddenPasswordFields++;
      }
      if (type === 'email' || name.indexOf('email') !== -1 || name.indexOf('user') !== -1) {
        signals.hasEmailField = true;
      }
      if (name.indexOf('card') !== -1 || name.indexOf('cvv') !== -1 ||
          name.indexOf('expir') !== -1 || name.indexOf('billing') !== -1 ||
          name.indexOf('ccnum') !== -1) {
        signals.hasPaymentFields = true;
      }
      if (name.indexOf('wallet') !== -1 || name.indexOf('seed') !== -1 ||
          name.indexOf('phrase') !== -1 || name.indexOf('private') !== -1 ||
          name.indexOf('mnemonic') !== -1) {
        signals.hasCryptoFields = true;
      }
    });

    // Form action analysis
    var forms = document.querySelectorAll('form');
    signals.formCount = forms.length;
    var currentDomain = window.location.hostname;
    forms.forEach(function (form) {
      var action = form.getAttribute('action') || '';
      if (action.startsWith('http') && action.indexOf(currentDomain) === -1) {
        signals.externalFormAction = true;
      }
    });

    // External scripts (data only — count, not URLs for privacy)
    var scripts = document.querySelectorAll('script[src]');
    var currentOrigin = window.location.origin;
    scripts.forEach(function (s) {
      var src = s.getAttribute('src') || '';
      if (src.startsWith('http') && src.indexOf(currentOrigin) === -1) {
        signals.externalScriptCount++;
      }
    });

    // Suspicious keyword detection (count only, no text content sent)
    var bodyText = document.body ? (document.body.innerText || '').toLowerCase() : '';
    SUSPICIOUS_PHRASES.forEach(function (phrase) {
      if (bodyText.indexOf(phrase) !== -1) {
        signals.suspiciousKeywords.push(phrase.split(' ').slice(0, 2).join('_')); // abbrev only
      }
    });

    // Only report if something notable found
    var shouldReport = signals.hasPasswordField || signals.hasPaymentFields ||
                       signals.hasCryptoFields  || signals.suspiciousKeywords.length > 0 ||
                       signals.externalFormAction;

    if (shouldReport) {
      chrome.runtime.sendMessage({
        type:    'PAGE_ANALYSIS',
        url:     window.location.href,
        signals: signals,
      }, function () {
        // Ignore response — fire and forget
        if (chrome.runtime.lastError) { /* background may not be ready yet */ }
      });
    }
  }

  // Run after DOM is ready
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    analyzePageContent();
  } else {
    document.addEventListener('DOMContentLoaded', analyzePageContent, { once: true });
  }

})();
