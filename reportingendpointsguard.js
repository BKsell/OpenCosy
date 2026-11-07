'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_ENTRY: 'bad-entry',
  INSECURE: 'insecure-endpoint',
  OVERLONG: 'overlong',
  TOO_MANY: 'too-many',
};

const HEADER = 'reporting-endpoints';
const MAX_LENGTH = 1024;
const MAX_ENDPOINTS = 8;
const NAME_RE = /^[a-z0-9_-]{1,64}$/i;

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

function parseEndpoint(entry) {
  const eq = entry.indexOf('=');
  if (eq < 0) return { ok: false, reason: REASON.BAD_ENTRY };
  const name = entry.slice(0, eq).trim();
  let url = entry.slice(eq + 1).trim().replace(/^"|"$/g, '');
  if (!NAME_RE.test(name) || !url) return { ok: false, reason: REASON.BAD_ENTRY };
  if (/[\u0000-\u001f\u007f"\\]/.test(url)) return { ok: false, reason: REASON.BAD_ENTRY };
  if (/^http:\/\//i.test(url)) return { ok: false, reason: REASON.INSECURE };
  if (!/^https:\/\//i.test(url)) return { ok: false, reason: REASON.BAD_ENTRY };
  url = url.replace(/\/+$/, '');
  return { ok: true, entry: name + '="' + url + '"' };
}

function applyReportingEndpointsGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING };
  const text = value.trim();
  if (!text) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.MISSING };
  }
  if (text.length > MAX_LENGTH) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.OVERLONG };
  }
  const entries = text.split(',');
  if (entries.length > MAX_ENDPOINTS) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const kept = [];
  let insecure = false;
  let bad = false;
  for (const entry of entries) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const parsed = parseEndpoint(trimmed);
    if (!parsed.ok) {
      if (parsed.reason === REASON.INSECURE) insecure = true;
      else bad = true;
      continue;
    }
    kept.push(parsed.entry);
  }
  if (kept.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: insecure ? REASON.INSECURE : REASON.BAD_ENTRY };
  }
  if (insecure || bad || kept.length !== entries.length) {
    headers[headerKey(headers, HEADER)] = kept.join(', ');
    return { changed: true, reason: insecure ? REASON.INSECURE : REASON.BAD_ENTRY };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyReportingEndpointsGuard };
