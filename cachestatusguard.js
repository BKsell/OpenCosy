'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  SUSPICIOUS_NAME: 'suspicious-name',
  SENSITIVE_PARAM: 'sensitive-param',
  FORWARD_CHAIN: 'forward-chain',
  TOO_MANY: 'too-many',
};

const HEADER = 'cache-status';
const MAX_VALUE_LENGTH = 1024;
const MAX_MEMBERS = 8;
const MAX_FWD = 3;
const SAFE_PARAMS = new Set(['hit', 'fwd', 'fwd-status', 'ttl']);
const SENSITIVE_PARAMS = new Set(['key', 'detail', 'collapsed', 'stored', 'cache-key', 'node']);

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

function isSafeName(name) {
  if (!name) return false;
  if (name.length > 64) return false;
  for (const ch of name) {
    const code = ch.charCodeAt(0);
    if (code < 0x20 || code > 0x7e) return false;
    if (ch === '/' || ch === '\\' || ch === '@' || ch === ':' || ch === '"' || ch === '(' || ch === ')' || ch === '.') {
      return false;
    }
  }
  return true;
}

function parseMember(token) {
  const parts = token.split(';').map((piece) => piece.trim()).filter(Boolean);
  if (parts.length === 0) return null;
  const name = parts[0];
  const params = [];
  for (const param of parts.slice(1)) {
    const eq = param.indexOf('=');
    if (eq < 0) {
      params.push({ key: param.toLowerCase(), value: null });
      continue;
    }
    const key = param.slice(0, eq).trim().toLowerCase();
    const value = param.slice(eq + 1).trim().replace(/^"|"$/g, '');
    if (!key) continue;
    params.push({ key, value });
  }
  return { name, params };
}

function sanitizeParams(params, findings) {
  const kept = [];
  let fwdCount = null;
  for (const param of params) {
    if (SENSITIVE_PARAMS.has(param.key)) {
      findings.sensitive = true;
      continue;
    }
    if (!SAFE_PARAMS.has(param.key)) {
      findings.sensitive = true;
      continue;
    }
    if (param.key === 'fwd') {
      const value = Number(param.value);
      if (!Number.isSafeInteger(value) || value < 0) {
        findings.malformed = true;
        continue;
      }
      fwdCount = value;
    }
    if (param.key === 'fwd-status') {
      const value = Number(param.value);
      if (!Number.isSafeInteger(value) || value < 100 || value > 599) {
        findings.malformed = true;
        continue;
      }
    }
    if (param.key === 'ttl') {
      const value = Number(param.value);
      if (!Number.isSafeInteger(value) || value < 0 || value > 31536000) {
        findings.malformed = true;
        continue;
      }
    }
    kept.push(param.value === null ? param.key : `${param.key}=${param.value}`);
  }
  if (fwdCount !== null && fwdCount > MAX_FWD) {
    findings.forwardChain = true;
    return kept.filter((item) => !item.startsWith('fwd='));
  }
  return kept;
}

function inspectCacheStatus(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, members: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, members: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, members: [] };
  const members = [];
  const findings = {};
  let reason = REASON.OK;
  for (const token of text.split(',')) {
    const member = parseMember(token);
    if (!member) continue;
    if (!isSafeName(member.name)) {
      reason = REASON.SUSPICIOUS_NAME;
      continue;
    }
    if (members.length >= MAX_MEMBERS) {
      reason = reason === REASON.OK ? REASON.TOO_MANY : reason;
      continue;
    }
    findings.sensitive = false;
    findings.malformed = false;
    findings.forwardChain = false;
    const params = sanitizeParams(member.params, findings);
    const rendered = params.length === 0 ? member.name : `${member.name}; ${params.join('; ')}`;
    if (findings.sensitive && reason === REASON.OK) reason = REASON.SENSITIVE_PARAM;
    if (findings.forwardChain && reason === REASON.OK) reason = REASON.FORWARD_CHAIN;
    if (findings.malformed && reason === REASON.OK) reason = REASON.MALFORMED;
    members.push(rendered);
  }
  if (members.length === 0 && reason === REASON.OK) reason = REASON.MALFORMED;
  return { reason, members };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'cache-status 合规';
    case REASON.MISSING:
      return '响应未声明 cache-status';
    case REASON.MALFORMED:
      return 'cache-status 取值非法，已剥除';
    case REASON.OVERLONG:
      return 'cache-status 超长，已剥除';
    case REASON.SUSPICIOUS_NAME:
      return 'cache-status 缓存标识可识别内部主机，已剥除';
    case REASON.SENSITIVE_PARAM:
      return 'cache-status 含敏感参数，已剥离';
    case REASON.FORWARD_CHAIN:
      return 'cache-status 转发跳数过长，已剥离';
    case REASON.TOO_MANY:
      return 'cache-status 成员过多，已截断';
    default:
      return 'cache-status 未识别状态';
  }
}

function applyCacheStatusGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, findings: [] };
  const result = inspectCacheStatus(value);
  const findings = [{ reason: result.reason, members: result.members }];
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, findings };
  }
  if (result.members.length === 0) {
    deleteHeader(headers, HEADER);
  } else {
    headers[headerKey(headers, HEADER)] = [result.members.join(', ')];
  }
  return { changed: true, reason: result.reason, findings };
}

module.exports = {
  REASON,
  HEADER,
  inspectCacheStatus,
  applyCacheStatusGuard,
  describeReason,
};
