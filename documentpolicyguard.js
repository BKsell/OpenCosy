'use strict';

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

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'document-policy 合规';
    case REASON.MISSING:
      return '响应未声明 document-policy';
    case REASON.MALFORMED:
      return 'document-policy 取值非法';
    case REASON.OVERLONG:
      return 'document-policy 超长';
    case REASON.UNKNOWN_DIRECTIVE:
      return 'document-policy 含未知或非法指令，已剔除';
    case REASON.DUPLICATE_DIRECTIVE:
      return 'document-policy 重复指令已去重';
    case REASON.BAD_VALUE:
      return 'document-policy 指令取值非法';
    case REASON.DOCUMENT_DOMAIN_ALLOWED:
      return 'document-policy 允许 document.domain，已剔除';
    case REASON.SYNC_XHR_ALLOWED:
      return 'document-policy 允许同步 XHR，已剔除';
    default:
      return 'document-policy 未识别状态';
  }
}

function applyDocumentPolicyGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, findings: [] };
  const result = inspectDocumentPolicy(value);
  const findings = [{ reason: result.reason, directives: result.directives }];
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, findings };
  }
  if (result.directives.length === 0) {
    deleteHeader(headers, HEADER);
  } else {
    headers[headerKey(headers, HEADER)] = [result.directives.join(', ')];
  }
  return { changed: true, reason: result.reason, findings };
}

module.exports = {
  REASON,
  HEADER,
  inspectDocumentPolicy,
  applyDocumentPolicyGuard,
  describeReason,
};
