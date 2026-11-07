'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  DEPRECATED: 'deprecated-policy',
  REPORT_URI_LEAK: 'report-uri-leak',
  UNSAFE_MAX_AGE: 'unsafe-max-age',
};

const HEADER = 'expect-ct';
const MAX_VALUE_LENGTH = 512;
const MAX_MAX_AGE = 86400;

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

function inspectExpectCt(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, directives: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, directives: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, directives: [] };

  let reason = REASON.OK;
  const note = (next) => {
    if (reason === REASON.OK) reason = next;
  };
  const directives = [];
  for (const raw of text.split(',')) {
    const piece = raw.trim().toLowerCase();
    if (!piece) continue;
    const eq = piece.indexOf('=');
    const name = (eq >= 0 ? piece.slice(0, eq) : piece).trim();
    const captured = eq >= 0 ? piece.slice(eq + 1).replace(/"/g, '').trim() : '';
    if (!name) {
      note(REASON.MALFORMED);
      continue;
    }
    if (name === 'max-age') {
      const seconds = Number(captured);
      if (!Number.isInteger(seconds) || seconds < 0) {
        note(REASON.MALFORMED);
        continue;
      }
      if (seconds > MAX_MAX_AGE) {
        note(REASON.UNSAFE_MAX_AGE);
        continue;
      }
      directives.push(`max-age=${seconds}`);
      continue;
    }
    if (name === 'report-uri') {
      note(REASON.REPORT_URI_LEAK);
      continue;
    }
    if (name === 'enforce') {
      directives.push('enforce');
      continue;
    }
    note(REASON.MALFORMED);
  }
  return { reason, directives };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'expect-ct 取值合规但该响应头已废弃';
    case REASON.MISSING:
      return '响应未声明 expect-ct';
    case REASON.MALFORMED:
      return 'expect-ct 指令非法';
    case REASON.OVERLONG:
      return 'expect-ct 超长';
    case REASON.DEPRECATED:
      return 'expect-ct 已废弃，整头剥除';
    case REASON.REPORT_URI_LEAK:
      return 'expect-ct 携带 report-uri 上报地址，已剥除';
    case REASON.UNSAFE_MAX_AGE:
      return 'expect-ct 缓存时长超出上限，已剥除';
    default:
      return 'expect-ct 未识别状态';
  }
}

function applyExpectCtGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, directives: [] };
  const result = inspectExpectCt(value);
  deleteHeader(headers, HEADER);
  return { changed: true, reason: REASON.DEPRECATED, directives: result.directives };
}

module.exports = {
  REASON,
  HEADER,
  inspectExpectCt,
  applyExpectCtGuard,
  describeReason,
};
