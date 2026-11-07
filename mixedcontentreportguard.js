'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'mixed-content-empty',
  INVALID: 'mixed-content-invalid',
  BLOCKABLE: 'mixed-content-blockable',
  DISPLAY_ONLY: 'mixed-content-display',
  CREDENTIALS: 'mixed-content-credentials',
  HOST_NOT_ALLOWED: 'mixed-content-host',
};

const BLOCKABLE_TYPES = new Set(['script', 'stylesheet', 'iframe', 'object', 'fetch', 'xhr', 'font', 'worker']);

function evaluateMixedContent(report, options) {
  const opts = options || {};
  const item = report || {};
  if (typeof item.url !== 'string' || item.url.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: '' };
  }
  let url;
  try {
    url = new URL(item.url.trim());
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: item.url.slice(0, 64) };
  }
  if (url.username || url.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, url: url.origin + url.pathname };
  }
  if (url.protocol !== 'http:') {
    return { ok: false, blocked: true, reason: REASON.INVALID, url: url.href };
  }
  const type = String(item.type || '').toLowerCase();
  if (BLOCKABLE_TYPES.has(type)) {
    return { ok: false, blocked: true, reason: REASON.BLOCKABLE, url: url.href, type, upgradeable: url.hostname !== '' };
  }
  if (opts.allowHosts && opts.allowHosts.length > 0) {
    const allowed = opts.allowHosts.includes(url.hostname.toLowerCase());
    if (!allowed) return { ok: false, blocked: true, reason: REASON.HOST_NOT_ALLOWED, url: url.href, host: url.hostname };
  }
  return { ok: true, blocked: false, reason: REASON.DISPLAY_ONLY, url: url.href, type };
}

function auditMixedContentBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateMixedContent(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ url: result.url, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no mixed content risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.url || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  BLOCKABLE_TYPES,
  evaluateMixedContent,
  auditMixedContentBatch,
  describeFindings,
};
