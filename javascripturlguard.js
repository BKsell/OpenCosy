'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'url-empty',
  SCRIPT_SCHEME: 'script-scheme',
  INLINE_DATA: 'inline-data-html',
  VBSCRIPT: 'vbscript-scheme',
  ENCODED_SCRIPT: 'encoded-script-scheme',
  NUL_BYTE: 'url-nul-byte',
  CONTROL_CHARS: 'url-control-chars',
};

const MAX_URL = 8192;
const BLOCKED = new Set(['javascript:', 'vbscript:', 'livescript:', 'mocha:']);
const INLINE = new Set(['data:', 'blob:']);

function decodeOnce(value) {
  try {
    return decodeURIComponent(value);
  } catch (err) {
    return value;
  }
}

function evaluateUrlScheme(value, options) {
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: String(value || '') };
  }
  if (value.length > MAX_URL) return { ok: false, blocked: true, reason: REASON.SCRIPT_SCHEME, url: '' };
  if (value.includes('\u0000')) return { ok: false, blocked: true, reason: REASON.NUL_BYTE, url: '' };
  if (/[\u0001-\u001f\u007f]/.test(value.replace(/[\r\n\t]/g, ''))) {
    return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, url: '' };
  }
  const collapsed = value.replace(/[\s\u0000-\u001f]+/g, '').toLowerCase();
  const decoded = decodeOnce(collapsed);
  for (const scheme of BLOCKED) {
    if (collapsed.startsWith(scheme) || decoded.startsWith(scheme)) {
      const reason = scheme === 'vbscript:' ? REASON.VBSCRIPT : REASON.SCRIPT_SCHEME;
      return { ok: false, blocked: true, reason, url: value.slice(0, 64) };
    }
  }
  for (const scheme of INLINE) {
    if (collapsed.startsWith(scheme) || decoded.startsWith(scheme)) {
      if (options && options.allowBlob === true && scheme === 'blob:') continue;
      return { ok: false, blocked: true, reason: REASON.INLINE_DATA, url: value.slice(0, 64) };
    }
  }
  if (/%6a%61%76%61%73%63%72%69%70%74/i.test(value)) {
    return { ok: false, blocked: true, reason: REASON.ENCODED_SCRIPT, url: value.slice(0, 64) };
  }
  let url;
  try {
    url = new URL(value);
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: value.slice(0, 64) };
  }
  if (BLOCKED.has(url.protocol)) return { ok: false, blocked: true, reason: REASON.SCRIPT_SCHEME, url: url.href };
  return { ok: true, blocked: false, reason: REASON.OK, url: url.href };
}

function auditSchemeBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateUrlScheme(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ url: result.url, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no script url risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.url || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateUrlScheme,
  auditSchemeBatch,
  describeFindings,
};
