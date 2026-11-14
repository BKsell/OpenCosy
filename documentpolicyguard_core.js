'use strict';
const { describeReasonTable } = require('./reasontext');
const { applyMemberListGuard } = require('./guardapply');

const { deleteHeader, firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  UNKNOWN_DIRECTIVE: 'unknown-directive',
  DUPLICATE_DIRECTIVE: 'duplicate-directive',
  BAD_VALUE: 'bad-value',
  DOCUMENT_DOMAIN_ALLOWED: 'document-domain-allowed',
  SYNC_XHR_ALLOWED: 'sync-xhr-allowed',
};

const HEADER = 'document-policy';
const MAX_VALUE_LENGTH = 2048;
const BOOLEAN_DIRECTIVES = new Set([
  'document-domain',
  'sync-xhr',
  'oversized-images',
  'unoptimized-images',
  'unsized-media',
  'layout-animations',
  'fonts',
  'js-profiling',
  'include-js-call-stacks-in-crash-reports',
  'cross-origin-isolated',
]);

function parseDirective(token) {
  const text = token.trim();
  if (!text) return null;
  const eq = text.indexOf('=');
  if (eq < 0) {
    const name = text.toLowerCase();
    if (!BOOLEAN_DIRECTIVES.has(name)) return { name, value: '', valid: false };
    return { name, value: '', valid: true };
  }
  const name = text.slice(0, eq).trim().toLowerCase();
  const value = text.slice(eq + 1).trim();
  if (!name) return null;
  if (!BOOLEAN_DIRECTIVES.has(name)) return { name, value, valid: false };
  if (value === '*') return { name, value, valid: true };
  if (value === 'none') return { name, value, valid: true };
  return { name, value, valid: false };
}

function inspectDocumentPolicy(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, directives: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, directives: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, directives: [] };
  const seen = new Set();
  const kept = [];
  let reason = REASON.OK;
  for (const raw of text.split(',')) {
    const directive = parseDirective(raw);
    if (!directive) continue;
    if (!directive.valid) {
      reason = reason === REASON.OK ? REASON.UNKNOWN_DIRECTIVE : reason;
      continue;
    }
    if (seen.has(directive.name)) {
      reason = reason === REASON.OK ? REASON.DUPLICATE_DIRECTIVE : reason;
      continue;
    }
    seen.add(directive.name);
    if (directive.name === 'document-domain' && directive.value === '*') {
      reason = REASON.DOCUMENT_DOMAIN_ALLOWED;
      continue;
    }
    if (directive.name === 'sync-xhr' && directive.value === '*') {
      if (reason === REASON.OK) reason = REASON.SYNC_XHR_ALLOWED;
      continue;
    }
    kept.push(directive.value === '' ? directive.name : `${directive.name}=${directive.value}`);
  }
  if (kept.length === 0 && reason !== REASON.OK) return { reason, directives: [] };
  return { reason, directives: kept };
}

const describeReason = describeReasonTable({
    [REASON.OK]: 'document-policy 合规',
    [REASON.MISSING]: '响应未声明 document-policy',
    [REASON.MALFORMED]: 'document-policy 取值非法',
    [REASON.OVERLONG]: 'document-policy 超长',
    [REASON.UNKNOWN_DIRECTIVE]: 'document-policy 含未知或非法指令，已剔除',
    [REASON.DUPLICATE_DIRECTIVE]: 'document-policy 重复指令已去重',
    [REASON.BAD_VALUE]: 'document-policy 指令取值非法',
    [REASON.DOCUMENT_DOMAIN_ALLOWED]: 'document-policy 允许 document.domain，已剔除',
    [REASON.SYNC_XHR_ALLOWED]: 'document-policy 允许同步 XHR，已剔除',
  }, 'document-policy 未识别状态');

function applyDocumentPolicyGuard(headers) {
  return applyMemberListGuard(headers, HEADER, inspectDocumentPolicy, { okReason: REASON.OK, missingReason: REASON.MISSING, field: 'directives', wrap: true });
}

module.exports = {
  REASON,
  HEADER,
  inspectDocumentPolicy,
  applyDocumentPolicyGuard,
  describeReason,
};
