'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  OVERLONG: 'overlong',
  TOO_MANY: 'too-many',
  BAD_ENTRY: 'bad-entry',
  BAD_PROTO: 'bad-proto',
  BAD_HOST: 'bad-host',
  BAD_NODE: 'bad-node',
};

const HEADER = 'forwarded';
const MAX_LENGTH = 512;
const MAX_ENTRIES = 3;
const HOST_RE = /^[a-z0-9.-]{1,253}(?::\d{1,5})?$/i;
const NODE_RE = /^(?:"?\[?[0-9a-f:.]{2,45}\]?(?::\d{1,5})?"?|unknown|_[a-z0-9._-]{1,63})$/i;

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

function splitParams(entry) {
  const params = [];
  let current = '';
  let quoted = false;
  for (const ch of entry) {
    if (ch === '"') quoted = !quoted;
    if (ch === ';' && !quoted) {
      params.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  params.push(current);
  return params;
}

function sanitizeNode(value) {
  const text = value.trim().replace(/^"|"$/g, '');
  if (!NODE_RE.test(text)) return '';
  if (text.includes('..')) return '';
  return text;
}

function inspectEntry(entry) {
  const parts = splitParams(entry);
  const kept = [];
  let badNode = false;
  let badProto = false;
  let badHost = false;
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) return { ok: false, entry: '' };
    const name = trimmed.slice(0, eq).trim().toLowerCase();
    const value = trimmed.slice(eq + 1).trim();
    if (name === 'for' || name === 'by') {
      const node = sanitizeNode(value);
      if (!node) {
        badNode = true;
        continue;
      }
      kept.push(name + '=' + node);
      continue;
    }
    if (name === 'proto') {
      const proto = value.toLowerCase();
      if (proto !== 'http' && proto !== 'https') {
        badProto = true;
        continue;
      }
      kept.push('proto=' + proto);
      continue;
    }
    if (name === 'host') {
      if (!HOST_RE.test(value) || value.length > 260 || value.includes('..')) {
        badHost = true;
        continue;
      }
      kept.push('host=' + value.toLowerCase());
      continue;
    }
  }
  const reason = badNode ? REASON.BAD_NODE : badProto ? REASON.BAD_PROTO : badHost ? REASON.BAD_HOST : REASON.OK;
  return { ok: kept.length > 0, entry: kept.join(';'), reason };
}

function applyForwardedGuard(headers) {
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
  if (entries.length > MAX_ENTRIES) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const kept = [];
  let reason = REASON.OK;
  for (const entry of entries) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
      reason = REASON.BAD_ENTRY;
      continue;
    }
    const inspected = inspectEntry(trimmed);
    if (!inspected.ok) {
      if (reason === REASON.OK) reason = inspected.reason === REASON.OK ? REASON.BAD_ENTRY : inspected.reason;
      continue;
    }
    if (inspected.reason !== REASON.OK && reason === REASON.OK) reason = inspected.reason;
    kept.push(inspected.entry);
  }
  if (kept.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_ENTRY : reason };
  }
  if (kept.length !== entries.length || reason !== REASON.OK) {
    headers[headerKey(headers, HEADER)] = kept.join(', ');
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_ENTRY : reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyForwardedGuard };
