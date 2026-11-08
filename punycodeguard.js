'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'idn-empty',
  PUNYCODE_MIXED: 'idn-punycode-mixed',
  SCRIPT_MIX: 'idn-script-mix',
  RAW_UNICODE: 'idn-raw-unicode',
  HOMOGRAPH_CONFUSABLE: 'idn-confusable',
  LABEL_TOO_LONG: 'idn-label-too-long',
};

const CONFUSABLE = ['xn--pn1', 'xn--d1ac', 'xn--80ak', 'xn--e1afmkfd'];
const ASCII_LABEL = /^[a-z0-9-]+$/;

function scriptsOf(label) {
  const hit = [];
  for (const ch of label) {
    const code = ch.codePointAt(0);
    if (code >= 0x0400 && code <= 0x04ff) hit.push('cyrillic');
    else if (code >= 0x0370 && code <= 0x03ff) hit.push('greek');
    else if (code >= 0x0590 && code <= 0x05ff) hit.push('hebrew');
    else if (code >= 0x0600 && code <= 0x06ff) hit.push('arabic');
    else if (code >= 0x4e00 && code <= 0x9fff) hit.push('han');
  }
  return hit;
}

function normalizeHost(host) {
  const value = typeof host === 'string' ? host.trim().toLowerCase().replace(/\.$/, '') : '';
  return value;
}

function evaluateIdn(host, options) {
  const opts = options || {};
  const value = normalizeHost(host);
  if (value === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  const labels = value.split('.');
  for (const label of labels) {
    if (label.length > 63) {
      return { ok: false, blocked: true, reason: REASON.LABEL_TOO_LONG, label: label.slice(0, 32), length: label.length };
    }
    if (label === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  }
  const punyLabels = labels.filter((label) => label.startsWith('xn--'));
  if (punyLabels.length > 0 && punyLabels.length !== labels.length && opts.requireUniform !== false) {
    return { ok: false, blocked: true, reason: REASON.PUNYCODE_MIXED, labels };
  }
  for (const label of labels) {
    if (!ASCII_LABEL.test(label)) {
      const scripts = scriptsOf(label);
      if (new Set(scripts).size > 1) {
        return { ok: false, blocked: true, reason: REASON.SCRIPT_MIX, label, scripts };
      }
      if (!label.startsWith('xn--') && scripts.length > 0) {
        return { ok: false, blocked: true, reason: REASON.RAW_UNICODE, label };
      }
    }
  }
  for (const label of punyLabels) {
    const body = label.slice(4);
    if (!/^[a-z0-9]+$/.test(body) || body.length < 4) {
      return { ok: false, blocked: true, reason: REASON.PUNYCODE_MIXED, label };
    }
  }
  if (opts.allowlist && opts.allowlist.length > 0 && !opts.allowlist.includes(value)) {
    for (const label of punyLabels) {
      const prefix = label.slice(0, 8);
      if (CONFUSABLE.includes(prefix)) {
        return { ok: false, blocked: true, reason: REASON.HOMOGRAPH_CONFUSABLE, label };
      }
    }
  }
  if (punyLabels.length > 0) {
    return { ok: false, blocked: false, reason: REASON.HOMOGRAPH_CONFUSABLE, labels: punyLabels, review: true };
  }
  return { ok: true, blocked: false, reason: REASON.OK, labels };
}

module.exports = {
  REASON,
  CONFUSABLE,
  evaluateIdn,
};
