'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  UNSAFE_CHARSET: 'unsafe-charset',
  DUPLICATE_CHARSET: 'duplicate-charset',
  BAD_CHARSET_TOKEN: 'bad-charset-token',
};

const MAX_HEADER_LENGTH = 200;
const UNSAFE_CHARSETS = new Set([
  'utf-7',
  'utf7',
  'utf-32',
  'utf32',
  'cesu-8',
  'cesu8',
  'scsu',
  'bocu-1',
  'bocu1',
  'hz-gb-2312',
]);
const TOKEN_RE = /^[!#$%&'*+.^_`|~0-9a-z-]+$/;
const HTML_TYPES = new Set(['text/html', 'application/xhtml+xml']);

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

function unquote(value) {
  const text = value.trim();
  if (text.length >= 2 && text.startsWith('"') && text.endsWith('"')) {
    return text.slice(1, -1).replace(/\\(.)/g, '$1');
  }
  return text;
}

function parseMediaType(value) {
  if (typeof value !== 'string') return null;
  const parts = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (ch === '"' && (i === 0 || value[i - 1] !== '\\')) quoted = !quoted;
    if (ch === ';' && !quoted) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  parts.push(current);
  const type = parts.shift().trim().toLowerCase();
  if (!type || !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(type)) return null;
  const params = [];
  for (const raw of parts) {
    const item = raw.trim();
    if (!item) return null;
    const eq = item.indexOf('=');
    if (eq <= 0) return null;
    const name = item.slice(0, eq).trim().toLowerCase();
    if (!TOKEN_RE.test(name)) return null;
    params.push({ name, value: unquote(item.slice(eq + 1)) });
  }
  return { type, params };
}

function serialize(type, params) {
  const pieces = [type];
  for (const param of params) pieces.push(`${param.name}=${param.value}`);
  return pieces.join('; ');
}

function inspectCharset(headers) {
  const value = firstValue(headers, 'content-type');
  if (!value) return { changed: false, reason: REASON.MISSING, header: null, type: null };
  if (value.length > MAX_HEADER_LENGTH) {
    return { changed: true, reason: REASON.OVERLONG, header: null, type: null };
  }
  const parsed = parseMediaType(value);
  if (!parsed) {
    return { changed: true, reason: REASON.MALFORMED, header: null, type: null };
  }
  const charsetParams = parsed.params.filter((p) => p.name === 'charset');
  if (!charsetParams.length) {
    return { changed: false, reason: REASON.OK, header: value, type: parsed.type };
  }
  const kept = [];
  let seenCharset = false;
  let reason = REASON.OK;
  for (const param of parsed.params) {
    if (param.name !== 'charset') {
      kept.push(param);
      continue;
    }
    const charset = param.value.toLowerCase();
    if (!TOKEN_RE.test(charset)) {
      reason = REASON.BAD_CHARSET_TOKEN;
      continue;
    }
    if (UNSAFE_CHARSETS.has(charset)) {
      reason = REASON.UNSAFE_CHARSET;
      continue;
    }
    if (seenCharset) {
      if (reason === REASON.OK) reason = REASON.DUPLICATE_CHARSET;
      continue;
    }
    seenCharset = true;
    kept.push({ name: 'charset', value: charset });
  }
  if (reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, header: value, type: parsed.type };
  }
  if (HTML_TYPES.has(parsed.type) && !seenCharset) {
    kept.push({ name: 'charset', value: 'utf-8' });
  }
  return { changed: true, reason, header: serialize(parsed.type, kept), type: parsed.type };
}

function applyCharsetGuard(headers) {
  const result = inspectCharset(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, 'content-type');
  if (key) {
    if (result.header) headers[key] = [result.header];
    else delete headers[key];
  }
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.UNSAFE_CHARSET:
      return 'Content-Type 指定了可构造 XSS 的字符集';
    case REASON.DUPLICATE_CHARSET:
      return 'Content-Type 重复声明 charset';
    case REASON.BAD_CHARSET_TOKEN:
      return 'charset 参数不是合法 token';
    case REASON.MALFORMED:
      return 'Content-Type 结构非法';
    case REASON.OVERLONG:
      return 'Content-Type 超长';
    default:
      return 'Content-Type 通过校验';
  }
}

module.exports = {
  REASON,
  MAX_HEADER_LENGTH,
  UNSAFE_CHARSETS,
  parseMediaType,
  inspectCharset,
  applyCharsetGuard,
  describeReason,
};
