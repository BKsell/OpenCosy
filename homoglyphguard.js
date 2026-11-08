'use strict';

const REASON = {
  OK: 'ok',
  BAD_URL: 'homoglyph-bad-url',
  PUNYCODE: 'homoglyph-punycode-host',
  MIXED_SCRIPT: 'homoglyph-mixed-script',
  COMBINING_MARK: 'homoglyph-combining-mark',
  ZERO_WIDTH: 'homoglyph-zero-width',
  LOOKALIKE_TLD: 'homoglyph-lookalike-tld',
  IP_LITERAL: 'homoglyph-ip-literal',
};

const MAX_URL = 8192;
const ZERO_WIDTH = /[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/;
const COMBINING = /[\u0300-\u036f]/;
const LATIN = /[a-z]/i;
const CYRILLIC = /[\u0400-\u04ff]/;
const GREEK = /[\u0370-\u03ff]/;
const LOOKALIKE_TLDS = new Set(['com', 'net', 'org', 'gov', 'co', 'cn']);

function decodeLabels(hostname) {
  const lower = String(hostname || '').toLowerCase();
  if (!lower.includes('xn--')) return { decoded: lower, punycode: false };
  const parts = lower.split('.');
  const out = [];
  let punycode = false;
  for (const part of parts) {
    if (part.startsWith('xn--')) {
      punycode = true;
      out.push(part.slice(4));
      continue;
    }
    out.push(part);
  }
  return { decoded: out.join('.'), punycode };
}

function evaluateHomoglyph(value, options) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL) {
    return { ok: false, blocked: true, reason: REASON.BAD_URL, host: '' };
  }
  let url;
  try {
    url = new URL(value);
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.BAD_URL, host: '' };
  }
  const host = url.hostname;
  if (ZERO_WIDTH.test(host)) return { ok: false, blocked: true, reason: REASON.ZERO_WIDTH, host };
  const { decoded, punycode } = decodeLabels(host);
  if (punycode) return { ok: false, blocked: true, reason: REASON.PUNYCODE, host };
  if (COMBINING.test(host)) return { ok: false, blocked: true, reason: REASON.COMBINING_MARK, host };
  const hasLatin = LATIN.test(host);
  const hasCyrillic = CYRILLIC.test(host);
  const hasGreek = GREEK.test(host);
  if ((hasLatin && (hasCyrillic || hasGreek)) || (hasCyrillic && hasGreek)) {
    return { ok: false, blocked: true, reason: REASON.MIXED_SCRIPT, host };
  }
  const tld = decoded.split('.').pop();
  if (LOOKALIKE_TLDS.has(tld) && /[\u0400-\u04ff\u0370-\u03ff]/.test(tld)) {
    return { ok: false, blocked: true, reason: REASON.LOOKALIKE_TLD, host };
  }
  if (options && options.blockIpLiteral === true && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
    return { ok: false, blocked: true, reason: REASON.IP_LITERAL, host };
  }
  if (options && typeof options.expectedHost === 'string' && decoded !== options.expectedHost.toLowerCase()) {
    return { ok: false, blocked: true, reason: REASON.MIXED_SCRIPT, host, expected: options.expectedHost };
  }
  return { ok: true, blocked: false, reason: REASON.OK, host: decoded };
}

function auditHomoglyphBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateHomoglyph(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ host: result.host, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no homoglyph risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.host || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateHomoglyph,
  auditHomoglyphBatch,
  describeFindings,
  decodeLabels,
};
