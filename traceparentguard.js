'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_FORMAT: 'bad-format',
  ALL_ZERO: 'all-zero-trace',
  BAD_FLAGS: 'bad-flags',
  OVERLONG: 'overlong',
};

const HEADER = 'traceparent';
const MAX_LENGTH = 128;
const VERSION_RE = /^[0-9a-f]{2}$/;
const TRACE_RE = /^[0-9a-f]{32}$/;
const SPAN_RE = /^[0-9a-f]{16}$/;
const FLAGS_RE = /^[0-9a-f]{2}$/;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function firstValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function inspectTraceparent(text) {
  if (text.length > MAX_LENGTH) return REASON.OVERLONG;
  const parts = text.split('-');
  if (parts.length !== 4) return REASON.BAD_FORMAT;
  const [version, traceId, spanId, flags] = parts;
  if (!VERSION_RE.test(version)) return REASON.BAD_FORMAT;
  if (version === 'ff') return REASON.BAD_FORMAT;
  if (!TRACE_RE.test(traceId) || !SPAN_RE.test(spanId)) return REASON.BAD_FORMAT;
  if (/^0+$/.test(traceId) || /^0+$/.test(spanId)) return REASON.ALL_ZERO;
  if (!FLAGS_RE.test(flags)) return REASON.BAD_FLAGS;
  if (version === '00' && parts.length !== 4) return REASON.BAD_FORMAT;
  return REASON.OK;
}

function applyTraceparentGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING };
  const text = value.trim().toLowerCase();
  if (!text) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.MISSING };
  }
  const verdict = inspectTraceparent(text);
  if (verdict === REASON.OK) return { changed: false, reason: REASON.OK };
  delete headers[headerKey(headers, HEADER)];
  return { changed: true, reason: verdict };
}

module.exports = { REASON, applyTraceparentGuard, inspectTraceparent };
