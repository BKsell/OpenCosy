'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'sse-empty',
  PLAINTEXT: 'sse-plaintext',
  CREDENTIALS: 'sse-credentials',
  MISSING_MIME: 'sse-mime-mismatch',
  NOSNIFF_MISSING: 'sse-nosniff-missing',
  TOO_MANY_RETRY: 'sse-retry-out-of-range',
};

function headerValue(headers, name) {
  const list = Array.isArray(headers) ? headers : [];
  for (const entry of list) {
    if (!Array.isArray(entry)) continue;
    if (String(entry[0] || '').toLowerCase() === name) return String(entry[1] || '');
  }
  return null;
}

function evaluateEventSource(url, headers, options) {
  const opts = options || {};
  const text = typeof url === 'string' ? url.trim() : '';
  if (text === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  let parsed;
  try {
    parsed = new URL(text);
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: text.slice(0, 48) };
  }
  if (parsed.protocol !== 'https:' && opts.allowHttp !== true) {
    return { ok: false, blocked: true, reason: REASON.PLAINTEXT, protocol: parsed.protocol };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, origin: parsed.origin };
  }
  const list = Array.isArray(headers) ? headers : [];
  const contentType = headerValue(list, 'content-type');
  if (contentType === null || !contentType.toLowerCase().includes('text/event-stream')) {
    return { ok: false, blocked: true, reason: REASON.MISSING_MIME, value: String(contentType || '').slice(0, 48) };
  }
  const nosniff = headerValue(list, 'x-content-type-options');
  if (nosniff === null || !nosniff.toLowerCase().includes('nosniff')) {
    return { ok: false, blocked: false, reason: REASON.NOSNIFF_MISSING };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin: parsed.origin };
}

function parseRetry(field) {
  const value = String(field || '').trim();
  if (!/^[0-9]+$/.test(value)) return null;
  const ms = Number(value);
  if (ms < 1000 || ms > 30000) return null;
  return ms;
}

module.exports = {
  REASON,
  evaluateEventSource,
  parseRetry,
};
