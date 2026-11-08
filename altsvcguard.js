'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  CROSS_ORIGIN: 'cross-origin',
  CLEAR_DIRECTIVE: 'clear-directive',
  TOO_MANY: 'too-many',
  BAD_PORT: 'bad-port',
};

const MAX_VALUE_LENGTH = 512;
const MAX_ENTRIES = 8;
const MAX_AUTHORITY_LENGTH = 200;

function lowerKeys(headers) {
  const map = {};
  if (!headers || typeof headers !== 'object') return map;
  for (const key of Object.keys(headers)) map[key.toLowerCase()] = key;
  return map;
}

function requestHost(details) {
  try {
    const host = new URL(details && details.url ? details.url : 'https://localhost/').hostname.toLowerCase();
    return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  } catch {
    return '';
  }
}

function splitEntries(value) {
  const entries = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (ch === '"' && value[i - 1] !== '\\') quoted = !quoted;
    if (ch === ',' && !quoted) {
      entries.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  entries.push(current.trim());
  return entries.filter(Boolean);
}

function authorityHost(authority) {
  const text = authority.trim();
  if (!text) return '';
  if (text.startsWith(':')) return '';
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end < 0) return null;
    return text.slice(1, end).toLowerCase();
  }
  const colon = text.lastIndexOf(':');
  if (colon > 0) return text.slice(0, colon).toLowerCase();
  return text.toLowerCase();
}

function authorityPort(authority) {
  const text = authority.trim();
  if (text.startsWith(':')) return text.slice(1);
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end < 0 || text[end + 1] !== ':') return '';
    return text.slice(end + 2);
  }
  const colon = text.lastIndexOf(':');
  if (colon > 0) return text.slice(colon + 1);
  return '';
}

function parseEntry(entry) {
  const match = /^([a-z0-9-]{1,20})\s*=\s*"([^"]{0,200})"/.exec(entry);
  if (!match) return null;
  const authority = match[2].trim();
  if (authority.length > MAX_AUTHORITY_LENGTH) return null;
  const port = authorityPort(authority);
  if (port && !/^\d{1,5}$/.test(port)) return null;
  if (port && Number(port) > 65535) return null;
  const host = authorityHost(authority);
  if (host === null) return null;
  return { protocol: match[1].toLowerCase(), authority, host, port };
}

function inspectAltSvc(headers, details) {
  const keys = lowerKeys(headers);
  const key = keys['alt-svc'];
  if (!key) return { changed: false, reason: REASON.MISSING, verdict: null };
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string' || !value.trim()) {
    delete headers[key];
    return { changed: true, reason: REASON.MALFORMED, verdict: null };
  }
  const text = value.trim();
  if (text.length > MAX_VALUE_LENGTH) {
    delete headers[key];
    return { changed: true, reason: REASON.MALFORMED, verdict: null };
  }
  if (text.toLowerCase() === 'clear') {
    delete headers[key];
    return { changed: true, reason: REASON.CLEAR_DIRECTIVE, verdict: null };
  }
  const entries = splitEntries(text);
  if (!entries.length || entries.length > MAX_ENTRIES) {
    delete headers[key];
    return { changed: true, reason: entries.length ? REASON.TOO_MANY : REASON.MALFORMED, verdict: null };
  }
  const pageHost = requestHost(details);
  const parsed = [];
  for (const entry of entries) {
    const item = parseEntry(entry);
    if (!item) {
      delete headers[key];
      return { changed: true, reason: REASON.MALFORMED, verdict: null };
    }
    if (item.port === '0') {
      delete headers[key];
      return { changed: true, reason: REASON.BAD_PORT, verdict: null };
    }
    if (item.host && pageHost && item.host !== pageHost) {
      delete headers[key];
      return { changed: true, reason: REASON.CROSS_ORIGIN, verdict: null };
    }
    parsed.push(item);
  }
  return { changed: false, reason: REASON.OK, verdict: parsed };
}

function applyAltSvcGuard(headers, details) {
  return inspectAltSvc(headers, details || {});
}

function describeReason(reason) {
  switch (reason) {
    case REASON.CROSS_ORIGIN:
      return 'Alt-Svc 指向了跨源主机';
    case REASON.CLEAR_DIRECTIVE:
      return 'Alt-Svc 下发 clear 指令';
    case REASON.MALFORMED:
      return 'Alt-Svc 结构非法';
    case REASON.TOO_MANY:
      return 'Alt-Svc 条目过多';
    case REASON.BAD_PORT:
      return 'Alt-Svc 端口非法';
    default:
      return 'Alt-Svc 通过校验';
  }
}

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  MAX_ENTRIES,
  splitEntries,
  parseEntry,
  inspectAltSvc,
  applyAltSvcGuard,
  describeReason,
};
