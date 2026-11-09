'use strict';
const { describeReasonFrom } = require('./reasontext');

const { hasControlCharsV2 } = require('./modutil');
const hasControlChars = hasControlCharsV2;

const { deleteHeader, firstValue, headerKey } = require('./headerutil');

const crypto = require('node:crypto');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  PATH_LEAK: 'path-leak',
  PREDICTABLE: 'predictable-validator',
  UNSAFE_CHARS: 'unsafe-chars',
};

const HEADER = 'etag';
const MAX_VALUE_LENGTH = 128;
const MAX_INNER_LENGTH = 96;
const PREDICTABLE_DIGITS = 6;

function opaqueTag(inner) {
  const hash = crypto.createHash('sha256').update(inner).digest('base64url');
  return hash.slice(0, 22);
}

function hasUnsafePathShape(inner) {
  if (inner.includes('/') || inner.includes('\\\\')) return true;
  if (inner.includes('..')) return true;
  if (/^[a-zA-Z]:/.test(inner)) return true;
  if (/\/(tmp|var|home|users|etc|root)\//i.test(inner)) return true;
  return false;
}

function looksPredictable(inner) {
  const digits = (inner.match(/\d/g) || []).length;
  if (digits < PREDICTABLE_DIGITS) return false;
  if (!/^[\d._-]+$/.test(inner)) return false;
  return true;
}

function inspectETag(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, tag: '', changed: false };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, tag: '', changed: false };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, tag: '', changed: false };
  let weak = false;
  let inner = text;
  if (text.startsWith('W/')) {
    weak = true;
    inner = text.slice(2);
  }
  if (inner.length < 2 || !inner.startsWith('"') || !inner.endsWith('"')) {
    return { reason: REASON.MALFORMED, tag: '', changed: false };
  }
  inner = inner.slice(1, -1);
  if (inner.length === 0) return { reason: REASON.MALFORMED, tag: '', changed: false };
  if (hasControlChars(inner)) return { reason: REASON.UNSAFE_CHARS, tag: '', changed: false };
  if (inner.length > MAX_INNER_LENGTH) return { reason: REASON.OVERLONG, tag: '', changed: false };
  for (const ch of inner) {
    if (ch.charCodeAt(0) > 0x7e) return { reason: REASON.UNSAFE_CHARS, tag: '', changed: false };
  }
  if (hasUnsafePathShape(inner)) {
    return { reason: REASON.PATH_LEAK, tag: `W/"${opaqueTag(inner)}"`, changed: true };
  }
  if (looksPredictable(inner)) {
    return { reason: REASON.PREDICTABLE, tag: `W/"${opaqueTag(inner)}"`, changed: true };
  }
  return { reason: REASON.OK, tag: weak ? `W/"${inner}"` : `"${inner}"`, changed: false };
}

function describeReason(reason) {
  return describeReasonFrom({
    [REASON.OK]: 'etag 合规',
    [REASON.MISSING]: '响应未声明 etag',
    [REASON.MALFORMED]: 'etag 取值非法，已剥除',
    [REASON.OVERLONG]: 'etag 超长，已剥除',
    [REASON.PATH_LEAK]: 'etag 暴露文件系统路径，已替换为不透明弱校验器',
    [REASON.PREDICTABLE]: 'etag 可由序号推算，已替换为不透明弱校验器',
    [REASON.UNSAFE_CHARS]: 'etag 含控制字符或非 ASCII，已剥除',
  }, reason, 'etag 未识别状态');
}

function applyETagGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, findings: [] };
  const result = inspectETag(value);
  const findings = [{ reason: result.reason, tag: result.tag }];
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, findings };
  }
  if (!result.tag) {
    deleteHeader(headers, HEADER);
  } else {
    headers[headerKey(headers, HEADER)] = [result.tag];
  }
  return { changed: true, reason: result.reason, findings };
}

module.exports = {
  REASON,
  HEADER,
  inspectETag,
  applyETagGuard,
  describeReason,
};
