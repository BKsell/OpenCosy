'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  WILDCARD: 'wildcard-charset',
  UNKNOWN_CHARSET: 'unknown-charset',
  DEPRECATED_HEADER: 'deprecated-header',
};

const HEADER = 'accept-charset';
const MAX_VALUE_LENGTH = 256;
const KNOWN_CHARSETS = new Set([
  'utf-8',
  'utf8',
  'us-ascii',
  'ascii',
  'iso-8859-1',
  'latin1',
  'windows-1252',
  'utf-16',
  'utf-16le',
  'utf-16be',
]);

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

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (key) delete headers[key];
}

function normalizeCharset(token) {
  const text = token.trim().toLowerCase();
  if (!text) return '';
  const semi = text.indexOf(';');
  return (semi >= 0 ? text.slice(0, semi) : text).trim();
}

function inspectAcceptCharset(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, charsets: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, charsets: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, charsets: [] };

  const seen = new Set();
  const kept = [];
  let reason = REASON.OK;
  const note = (next) => {
    if (reason === REASON.OK) reason = next;
  };

  for (const raw of text.split(',')) {
    const charset = normalizeCharset(raw);
    if (!charset) continue;
    if (charset === '*' || charset === 'any') {
      note(REASON.WILDCARD);
      continue;
    }
    if (!KNOWN_CHARSETS.has(charset)) {
      note(REASON.UNKNOWN_CHARSET);
      continue;
    }
    if (seen.has(charset)) continue;
    seen.add(charset);
    kept.push(charset);
  }

  if (kept.length === 0 && reason !== REASON.OK) return { reason, charsets: [] };
  return { reason, charsets: kept };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'accept-charset 取值合规但该响应头已废弃';
    case REASON.MISSING:
      return '响应未声明 accept-charset';
    case REASON.MALFORMED:
      return 'accept-charset 取值非法';
    case REASON.OVERLONG:
      return 'accept-charset 超长';
    case REASON.WILDCARD:
      return 'accept-charset 声明通配字符集，已剔除';
    case REASON.UNKNOWN_CHARSET:
      return 'accept-charset 含未知字符集，已剔除';
    case REASON.DEPRECATED_HEADER:
      return 'accept-charset 已废弃，整头剥除';
    default:
      return 'accept-charset 未识别状态';
  }
}

function applyAcceptCharsetGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, charsets: [] };
  const result = inspectAcceptCharset(value);
  deleteHeader(headers, HEADER);
  return { changed: true, reason: REASON.DEPRECATED_HEADER, charsets: result.charsets };
}

module.exports = {
  REASON,
  HEADER,
  inspectAcceptCharset,
  applyAcceptCharsetGuard,
  describeReason,
};
