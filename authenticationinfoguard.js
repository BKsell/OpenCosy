'use strict';
const { describeReasonTable } = require('./reasontext');

const { deleteHeader, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  CONTROL_CHARS: 'control-chars',
  UNKNOWN_PARAM: 'unknown-param',
  BAD_BASE64: 'bad-base64',
  BAD_NC: 'bad-nc',
  BAD_QOP: 'bad-qop',
  NONCE_TOO_LONG: 'nonce-too-long',
  OVERLONG: 'overlong',
  MALFORMED: 'malformed',
};

const MAX_VALUE_LENGTH = 512;
const MAX_NONCE_LENGTH = 128;
const BASE64_PATTERN = /^[A-Za-z0-9+/]{1,128}={0,2}$/;
const NC_PATTERN = /^[0-9a-fA-F]{8}$/;
const QOP_SET = new Set(['auth', 'auth-int']);
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;

function inspectAuthenticationInfo(value) {
  if (value === undefined || value === null) return { reason: REASON.MISSING };
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  if (CONTROL_PATTERN.test(text)) return { reason: REASON.CONTROL_CHARS };
  const parts = text.split(',').map((item) => item.trim()).filter(Boolean);
  if (parts.length === 0) return { reason: REASON.MALFORMED };
  const params = {};
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq <= 0) return { reason: REASON.MALFORMED, param: part.slice(0, 32) };
    const name = part.slice(0, eq).trim().toLowerCase();
    const rawValue = part.slice(eq + 1).trim().replace(/^"(.*)"$/, '$1');
    if (!rawValue) return { reason: REASON.MALFORMED, param: name };
    if (name === 'nextnonce') {
      if (rawValue.length > MAX_NONCE_LENGTH) return { reason: REASON.NONCE_TOO_LONG, param: name };
      params[name] = rawValue;
      continue;
    }
    if (name === 'qop') {
      if (!QOP_SET.has(rawValue.toLowerCase())) return { reason: REASON.BAD_QOP, param: name };
      params[name] = rawValue.toLowerCase();
      continue;
    }
    if (name === 'rspauth') {
      if (!BASE64_PATTERN.test(rawValue)) return { reason: REASON.BAD_BASE64, param: name };
      params[name] = rawValue;
      continue;
    }
    if (name === 'cnonce') {
      if (rawValue.length > MAX_NONCE_LENGTH) return { reason: REASON.NONCE_TOO_LONG, param: name };
      params[name] = rawValue;
      continue;
    }
    if (name === 'nc') {
      if (!NC_PATTERN.test(rawValue)) return { reason: REASON.BAD_NC, param: name };
      params[name] = rawValue;
      continue;
    }
    return { reason: REASON.UNKNOWN_PARAM, param: name.slice(0, 32) };
  }
  return { reason: REASON.OK, params };
}

function applyAuthenticationInfoGuard(headers) {
  const key = headerKey(headers, 'authentication-info');
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  if (Array.isArray(raw) && raw.length > 1) {
    delete headers[key];
    return { changed: true, reason: REASON.MULTI_VALUE, previous: raw.slice(0, 3) };
  }
  const value = Array.isArray(raw) ? raw[0] : raw;
  const verdict = inspectAuthenticationInfo(value);
  if (verdict.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, params: Object.keys(verdict.params) };
  }
  delete headers[key];
  return { changed: true, reason: verdict.reason, param: verdict.param || null };
}

const describeReason = describeReasonTable({
    [REASON.OK]: 'Authentication-Info 参数合法',
    [REASON.MISSING]: '未声明 Authentication-Info',
    [REASON.CONTROL_CHARS]: 'Authentication-Info 含控制字符',
    [REASON.UNKNOWN_PARAM]: 'Authentication-Info 含未知参数',
    [REASON.BAD_BASE64]: 'Authentication-Info rspauth 不是合法 base64',
    [REASON.BAD_NC]: 'Authentication-Info nc 不是 8 位十六进制',
    [REASON.BAD_QOP]: 'Authentication-Info qop 取值非法',
    [REASON.NONCE_TOO_LONG]: 'Authentication-Info nonce 超长',
    [REASON.OVERLONG]: 'Authentication-Info 取值超长',
    [REASON.MALFORMED]: 'Authentication-Info 取值无法解析',
  }, 'Authentication-Info 未知状态');

module.exports = {
  REASON,
  inspectAuthenticationInfo,
  applyAuthenticationInfoGuard,
  describeReason,
};
