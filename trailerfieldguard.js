'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  DUPLICATE: 'duplicate',
  FORBIDDEN_NAME: 'forbidden-name',
  TOO_MANY: 'too-many',
};

const HEADER = 'trailer';
const MAX_VALUE_LENGTH = 512;
const MAX_FIELDS = 16;
const FORBIDDEN_FIELDS = new Set([
  'set-cookie',
  'set-cookie2',
  'authorization',
  'www-authenticate',
  'proxy-authenticate',
  'content-length',
  'content-encoding',
  'content-type',
  'transfer-encoding',
  'trailer',
  'host',
  'connection',
  'keep-alive',
  'upgrade',
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

function isFieldToken(name) {
  if (!name) return false;
  if (name.length > 64) return false;
  for (const ch of name) {
    const code = ch.charCodeAt(0);
    if (code < 0x21 || code > 0x7e) return false;
    if (ch === '(' || ch === ')' || ch === ',' || ch === '/' || ch === ':' || ch === ';' || ch === '"') return false;
  }
  return true;
}

function inspectTrailer(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, fields: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, fields: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, fields: [] };
  const seen = new Set();
  const fields = [];
  let reason = REASON.OK;
  for (const raw of text.split(',')) {
    const name = raw.trim().toLowerCase();
    if (!name) continue;
    if (!isFieldToken(name)) {
      if (reason === REASON.OK) reason = REASON.MALFORMED;
      continue;
    }
    if (FORBIDDEN_FIELDS.has(name)) {
      if (reason === REASON.OK) reason = REASON.FORBIDDEN_NAME;
      continue;
    }
    if (seen.has(name)) {
      if (reason === REASON.OK) reason = REASON.DUPLICATE;
      continue;
    }
    if (fields.length >= MAX_FIELDS) {
      if (reason === REASON.OK) reason = REASON.TOO_MANY;
      continue;
    }
    seen.add(name);
    fields.push(name);
  }
  if (fields.length === 0 && reason === REASON.OK) reason = REASON.MALFORMED;
  return { reason, fields };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'trailer 声明合规';
    case REASON.MISSING:
      return '响应未声明 trailer';
    case REASON.MALFORMED:
      return 'trailer 含非法字段名，已剥除';
    case REASON.OVERLONG:
      return 'trailer 声明超长，已剥除';
    case REASON.DUPLICATE:
      return 'trailer 字段重复，已去重';
    case REASON.FORBIDDEN_NAME:
      return 'trailer 声明了禁止的字段，已剥除';
    case REASON.TOO_MANY:
      return 'trailer 字段过多，已截断';
    default:
      return 'trailer 未识别状态';
  }
}

function applyTrailerFieldGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, findings: [] };
  const result = inspectTrailer(value);
  const findings = [{ reason: result.reason, fields: result.fields }];
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, findings };
  }
  if (result.fields.length === 0) {
    deleteHeader(headers, HEADER);
  } else {
    headers[headerKey(headers, HEADER)] = [result.fields.join(', ')];
  }
  return { changed: true, reason: result.reason, findings };
}

module.exports = {
  REASON,
  HEADER,
  inspectTrailer,
  applyTrailerFieldGuard,
  describeReason,
};
