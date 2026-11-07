'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty-headers',
  BAD_NAME: 'invalid-header-name',
  CONTROL_CHAR: 'control-character',
  OBS_FOLD: 'obs-fold',
  OVERLONG: 'overlong-value',
  TOO_MANY: 'too-many-headers',
};

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const MAX_NAME_LENGTH = 64;
const MAX_VALUE_LENGTH = 4096;
const MAX_HEADERS = 128;

function scanValue(value) {
  if (typeof value !== 'string') return { reason: REASON.CONTROL_CHAR, cleaned: '' };
  if (value.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, cleaned: '' };
  let cleaned = '';
  let obsFold = false;
  let control = false;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 13 || code === 10) {
      control = true;
      const next = value[i + 1];
      if ((code === 13 && next === '\n') || code === 10) obsFold = true;
      continue;
    }
    if (code === 0) {
      control = true;
      continue;
    }
    if (code < 32 && code !== 9) {
      control = true;
      continue;
    }
    if (code === 127) {
      control = true;
      continue;
    }
    cleaned += value[i];
  }
  if (control) {
    return { reason: obsFold ? REASON.OBS_FOLD : REASON.CONTROL_CHAR, cleaned: '' };
  }
  return { reason: REASON.OK, cleaned: value };
}

function inspectHeaders(headers) {
  if (!headers || typeof headers !== 'object') {
    return { present: false, findings: [], removals: [] };
  }
  const keys = Object.keys(headers);
  if (!keys.length) return { present: false, findings: [], removals: [] };
  const findings = [];
  const removals = [];
  if (keys.length > MAX_HEADERS) {
    findings.push({ header: '', reason: REASON.TOO_MANY, detail: String(keys.length) });
    return { present: true, findings, removals };
  }
  for (const key of keys) {
    if (key.length > MAX_NAME_LENGTH || !TOKEN.test(key)) {
      findings.push({ header: key, reason: REASON.BAD_NAME, detail: '' });
      removals.push(key);
      continue;
    }
    const raw = headers[key];
    const list = Array.isArray(raw) ? raw : [raw];
    let badReason = null;
    for (const item of list) {
      const scanned = scanValue(item);
      if (scanned.reason !== REASON.OK) {
        badReason = scanned.reason;
        break;
      }
    }
    if (badReason) {
      findings.push({ header: key, reason: badReason, detail: '' });
      removals.push(key);
    }
  }
  return { present: true, findings, removals };
}

function applyHeaderInjectionGuard(headers) {
  const result = inspectHeaders(headers);
  if (!result.present) return { changed: false, reason: REASON.EMPTY, removed: 0 };
  if (!result.removals.length) {
    const reason = result.findings.length ? result.findings[0].reason : REASON.OK;
    return { changed: false, reason, removed: 0 };
  }
  for (const key of result.removals) {
    if (Object.prototype.hasOwnProperty.call(headers, key)) delete headers[key];
  }
  return {
    changed: true,
    reason: result.findings[0].reason,
    removed: result.removals.length,
  };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return '响应头为空';
    case REASON.BAD_NAME:
      return '响应头名含非法字符，已移除';
    case REASON.CONTROL_CHAR:
      return '响应头值含控制字符，已移除';
    case REASON.OBS_FOLD:
      return '响应头值含折行，已移除';
    case REASON.OVERLONG:
      return '响应头值超长，已移除';
    case REASON.TOO_MANY:
      return '响应头数量超限';
    default:
      return '响应头通过校验';
  }
}

module.exports = {
  REASON,
  MAX_NAME_LENGTH,
  MAX_VALUE_LENGTH,
  MAX_HEADERS,
  scanValue,
  inspectHeaders,
  applyHeaderInjectionGuard,
  describeReason,
};
