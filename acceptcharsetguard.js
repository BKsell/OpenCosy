'use strict';
const { describeReasonTable } = require('./reasontext');

const { normalizeCharset } = require('./modutil');

const { deleteHeader, firstValue, headerKey } = require('./headerutil');

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

const describeReason = describeReasonTable({
    [REASON.OK]: 'accept-charset 取值合规但该响应头已废弃',
    [REASON.MISSING]: '响应未声明 accept-charset',
    [REASON.MALFORMED]: 'accept-charset 取值非法',
    [REASON.OVERLONG]: 'accept-charset 超长',
    [REASON.WILDCARD]: 'accept-charset 声明通配字符集，已剔除',
    [REASON.UNKNOWN_CHARSET]: 'accept-charset 含未知字符集，已剔除',
    [REASON.DEPRECATED_HEADER]: 'accept-charset 已废弃，整头剥除',
  }, 'accept-charset 未识别状态');

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
