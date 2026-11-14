'use strict';
const { describeReasonTable } = require('./reasontext');
const { applyMemberListGuard } = require('./guardapply_core');

const { normalizeCharset } = require('./modutil_core');
const normalizeType = normalizeCharset;

require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  WILDCARD: 'wildcard-accepted',
  UNSAFE_TYPE: 'unsafe-media-type',
  UNKNOWN_TYPE: 'unknown-media-type',
  DUPLICATE: 'duplicate-media-type',
};

const HEADER = 'accept-patch';
const MAX_VALUE_LENGTH = 512;
const ALLOWED_TYPES = new Set([
  'application/json-patch+json',
  'application/merge-patch+json',
  'application/ld+json',
  'application/apply-patch+yaml',
  'text/plain',
]);

function inspectAcceptPatch(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, types: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, types: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, types: [] };

  const seen = new Set();
  const kept = [];
  let reason = REASON.OK;
  const note = (next) => {
    if (reason === REASON.OK) reason = next;
  };

  for (const raw of text.split(',')) {
    const type = normalizeType(raw);
    if (!type) continue;
    if (type === '*' || type === '*/*' || type === 'application/*') {
      note(REASON.WILDCARD);
      continue;
    }
    if (type.includes('html') || type.includes('xml') || type.includes('javascript')) {
      note(REASON.UNSAFE_TYPE);
      continue;
    }
    if (!ALLOWED_TYPES.has(type)) {
      note(REASON.UNKNOWN_TYPE);
      continue;
    }
    if (seen.has(type)) {
      note(REASON.DUPLICATE);
      continue;
    }
    seen.add(type);
    kept.push(type);
  }

  if (kept.length === 0 && reason !== REASON.OK) return { reason, types: [] };
  return { reason, types: kept };
}

const describeReason = describeReasonTable({
    [REASON.OK]: 'accept-patch 合规',
    [REASON.MISSING]: '响应未声明 accept-patch',
    [REASON.MALFORMED]: 'accept-patch 取值非法',
    [REASON.OVERLONG]: 'accept-patch 超长',
    [REASON.WILDCARD]: 'accept-patch 接受通配补丁类型，已剔除',
    [REASON.UNSAFE_TYPE]: 'accept-patch 接受可执行或可渲染类型，已剔除',
    [REASON.UNKNOWN_TYPE]: 'accept-patch 类型不在白名单，已剔除',
    [REASON.DUPLICATE]: 'accept-patch 重复类型已去重',
  }, 'accept-patch 未识别状态');

function applyAcceptPatchGuard(headers) {
  return applyMemberListGuard(headers, HEADER, inspectAcceptPatch, { okReason: REASON.OK, missingReason: REASON.MISSING, field: 'types', wrap: false });
}

module.exports = {
  REASON,
  HEADER,
  inspectAcceptPatch,
  applyAcceptPatchGuard,
  describeReason,
};
