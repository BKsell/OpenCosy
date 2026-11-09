'use strict';
const { describeReasonFrom } = require('./reasontext');

const { deleteHeader, firstValue, headerKey } = require('./headerutil');

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
  return describeReasonFrom({
    [REASON.OK]: 'trailer 声明合规',
    [REASON.MISSING]: '响应未声明 trailer',
    [REASON.MALFORMED]: 'trailer 含非法字段名，已剥除',
    [REASON.OVERLONG]: 'trailer 声明超长，已剥除',
    [REASON.DUPLICATE]: 'trailer 字段重复，已去重',
    [REASON.FORBIDDEN_NAME]: 'trailer 声明了禁止的字段，已剥除',
    [REASON.TOO_MANY]: 'trailer 字段过多，已截断',
  }, reason, 'trailer 未识别状态');
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
