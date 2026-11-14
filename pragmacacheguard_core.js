'use strict';
const { describeReasonTable } = require('./reasontext');

const { applyVerdictHeaderGuard } = require('./guardapply');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_DIRECTIVE: 'bad-directive',
  MULTI_VALUE: 'multi-value',
  OVERLONG: 'overlong',
  MALFORMED: 'malformed',
};

const MAX_VALUE_LENGTH = 64;
const ALLOWED_DIRECTIVES = new Set(['no-cache']);

function inspectPragma(value) {
  if (value === undefined || value === null) return { reason: REASON.MISSING };
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  if (text.includes(',')) return { reason: REASON.MULTI_VALUE };
  const token = text.toLowerCase();
  if (!ALLOWED_DIRECTIVES.has(token)) return { reason: REASON.BAD_DIRECTIVE, token };
  return { reason: REASON.OK, token };
}

function applyPragmaCacheGuard(headers) {
  return applyVerdictHeaderGuard(headers, 'pragma', inspectPragma, {
    okReason: REASON.OK,
    missingReason: REASON.MISSING,
    multiReason: REASON.MULTI_VALUE,
    okField: 'token',
    failField: 'token',
  });
}

const describeReason = describeReasonTable({
    [REASON.OK]: 'Pragma 仅保留 no-cache',
    [REASON.MISSING]: '未声明 Pragma',
    [REASON.BAD_DIRECTIVE]: 'Pragma 使用非标准缓存指令',
    [REASON.MULTI_VALUE]: 'Pragma 出现多个取值',
    [REASON.OVERLONG]: 'Pragma 取值超长',
    [REASON.MALFORMED]: 'Pragma 取值无法解析',
  }, 'Pragma 未知状态');

module.exports = {
  REASON,
  inspectPragma,
  applyPragmaCacheGuard,
  describeReason,
};
