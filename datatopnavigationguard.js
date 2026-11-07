'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-url',
  DATA_TOPLEVEL: 'data-url-top-level',
  BLOB_TOPLEVEL: 'blob-url-top-level',
  JAVASCRIPT: 'javascript-url',
  ACTIVE_CONTENT: 'active-content-payload',
  TOO_LARGE: 'payload-too-large',
  DOWNLOAD_ALLOWED: 'download-only',
};

const MAX_DATA_URL = 2 * 1024 * 1024;
const ACTIVE_MARKERS = ['<script', '<iframe', '<object', '<embed', 'javascript:', 'onerror=', 'onload='];

function isDataUrl(value) {
  return typeof value === 'string' && value.slice(0, 5).toLowerCase() === 'data:';
}

function isBlobUrl(value) {
  return typeof value === 'string' && value.slice(0, 5).toLowerCase() === 'blob:';
}

function isJavaScriptUrl(value) {
  if (typeof value !== 'string') return false;
  const compact = value.replace(/[\s\u0000-\u001f]/g, '').toLowerCase();
  return compact.slice(0, 11) === 'javascript:';
}

function parseDataUrl(value) {
  const comma = value.indexOf(',');
  if (comma < 0) return null;
  const meta = value.slice(5, comma);
  const payload = value.slice(comma + 1);
  const parts = meta.split(';');
  const mime = (parts[0] || 'text/plain').toLowerCase();
  const base64 = parts.includes('base64');
  return { mime, base64, payload, length: value.length };
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const url = req.url;
  if (typeof url !== 'string' || !url) return { blocked: true, reason: REASON.INVALID };
  if (isJavaScriptUrl(url)) return { blocked: true, reason: REASON.JAVASCRIPT };
  if (isDataUrl(url)) {
    const parsed = parseDataUrl(url);
    if (!parsed) return { blocked: true, reason: REASON.INVALID };
    if (parsed.length > MAX_DATA_URL) return { blocked: true, reason: REASON.TOO_LARGE, size: parsed.length };
    const haystack = parsed.base64 ? Buffer.from(parsed.payload, 'base64').toString('latin1').toLowerCase() : decodeURIComponent(parsed.payload.slice(0, 4096)).toLowerCase();
    if (ACTIVE_MARKERS.some((m) => haystack.includes(m))) {
      return { blocked: true, reason: REASON.ACTIVE_CONTENT, mime: parsed.mime };
    }
    if (req.topLevel) return { blocked: true, reason: REASON.DATA_TOPLEVEL, mime: parsed.mime };
    return { blocked: false, reason: REASON.OK, mime: parsed.mime };
  }
  if (isBlobUrl(url)) {
    if (req.topLevel) return { blocked: true, reason: REASON.BLOB_TOPLEVEL };
    return { blocked: false, reason: REASON.OK };
  }
  return { blocked: false, reason: REASON.OK };
}

function applyDataTopNavigationGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  if (!result.blocked && req.isDownload) {
    return { blocked: false, reason: REASON.DOWNLOAD_ALLOWED, action: 'download', mime: result.mime || '' };
  }
  if (result.blocked && req.isDownload && result.reason === REASON.DATA_TOPLEVEL) {
    return { blocked: false, reason: REASON.DOWNLOAD_ALLOWED, action: 'download' };
  }
  return {
    blocked: result.blocked,
    reason: result.reason,
    action: result.blocked ? 'block' : 'allow',
    mime: result.mime || '',
  };
}

function sanitizeDataUrl(value, allowedMimes) {
  if (!isDataUrl(value)) return { url: value, changed: false, mime: '' };
  const parsed = parseDataUrl(value);
  if (!parsed) return { url: '', changed: true, mime: '' };
  const allow = Array.isArray(allowedMimes) ? allowedMimes.map((m) => String(m).toLowerCase()) : [];
  if (allow.length > 0 && !allow.includes(parsed.mime)) return { url: '', changed: true, mime: parsed.mime };
  return { url: value, changed: false, mime: parsed.mime };
}

function auditDataNavigationBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let blocked = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.blocked) blocked += 1;
    if (result.reason !== REASON.OK) findings.push({ url: String((item && item.url) || '').slice(0, 64), reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { blocked, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no data navigation risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyDataTopNavigationGuard,
  auditDataNavigationBatch,
  describeFindings,
  sanitizeDataUrl,
  parseDataUrl,
};
