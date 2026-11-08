'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'data-url-empty',
  INVALID: 'data-url-invalid',
  DANGEROUS_MIME: 'data-url-dangerous-mime',
  MIME_NOT_ALLOWED: 'data-url-mime-not-allowed',
  OVERSIZED: 'data-url-oversized',
  BASE64_INVALID: 'data-url-base64-invalid',
};

const DEFAULT_ALLOW = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'text/plain'];
const DANGEROUS = ['text/html', 'text/javascript', 'application/javascript', 'image/svg+xml', 'application/xhtml+xml'];
const MAX_DEFAULT = 32768;

function parseDataUrl(url) {
  const text = typeof url === 'string' ? url.trim() : '';
  if (text === '') return { ok: false, reason: REASON.EMPTY };
  if (!text.toLowerCase().startsWith('data:')) return { ok: false, reason: REASON.INVALID };
  const comma = text.indexOf(',');
  if (comma === -1) return { ok: false, reason: REASON.INVALID };
  const meta = text.slice(5, comma);
  const payload = text.slice(comma + 1);
  const parts = meta.split(';').map((part) => part.trim());
  const mime = (parts[0] || '').toLowerCase() || 'text/plain';
  const base64 = parts.includes('base64');
  return { ok: true, mime, base64, payload, length: text.length };
}

function evaluateDataUrl(url, options) {
  const opts = options || {};
  const parsed = parseDataUrl(url);
  if (!parsed.ok) return { ok: false, blocked: true, reason: parsed.reason };
  const allow = Array.isArray(opts.allowMime) && opts.allowMime.length > 0 ? opts.allowMime : DEFAULT_ALLOW;
  const limit = typeof opts.maxBytes === 'number' && opts.maxBytes > 0 ? opts.maxBytes : MAX_DEFAULT;
  if (DANGEROUS.includes(parsed.mime)) {
    return { ok: false, blocked: true, reason: REASON.DANGEROUS_MIME, mime: parsed.mime };
  }
  if (!allow.includes(parsed.mime)) {
    return { ok: false, blocked: true, reason: REASON.MIME_NOT_ALLOWED, mime: parsed.mime };
  }
  if (parsed.length > limit) {
    return { ok: false, blocked: true, reason: REASON.OVERSIZED, size: parsed.length, limit };
  }
  if (parsed.base64) {
    const stripped = parsed.payload.replace(/%20/g, '');
    if (!/^[A-Za-z0-9+/=]+$/.test(stripped)) {
      return { ok: false, blocked: true, reason: REASON.BASE64_INVALID, size: stripped.length };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, mime: parsed.mime, base64: parsed.base64, size: parsed.length };
}

module.exports = {
  REASON,
  DEFAULT_ALLOW,
  DANGEROUS,
  MAX_DEFAULT,
  parseDataUrl,
  evaluateDataUrl,
};
