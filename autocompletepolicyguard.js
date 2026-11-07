'use strict';

const REASON = {
  OK: 'ok',
  SENSITIVE_AUTOCOMPLETE: 'sensitive-autocomplete-on',
  WEAK_AUTOCOMPLETE: 'weak-autocomplete-token',
  CROSS_SITE_LEAK: 'cross-site-autocomplete',
  MISSING_OFF: 'missing-off-for-secret',
};

const SECRET_TYPES = new Set(['password', 'new-password', 'current-password', 'one-time-code']);
const SENSITIVE_NAMES = new Set(['password', 'passwd', 'pwd', 'otp', 'totp', 'cvv', 'cvc', 'ssn', 'token', 'apikey', 'secret']);
const VALID = new Set(['on', 'off', 'name', 'honorific-prefix', 'given-name', 'family-name', 'email', 'tel', 'street-address', 'address-line1', 'postal-code', 'country', 'cc-number', 'cc-exp', 'cc-csc', 'username', 'current-password', 'new-password', 'one-time-code', 'webauthn']);

function normalize(value) {
  return String(value || '').trim().toLowerCase();
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const type = normalize(req.fieldType);
  const name = normalize(req.name);
  const autocomplete = normalize(req.autocomplete);
  const token = autocomplete.split(/\s+/)[0] || '';
  if (SECRET_TYPES.has(type) || SENSITIVE_NAMES.has(name)) {
    if (autocomplete === 'on' || autocomplete === '') {
      return { blocked: true, reason: REASON.SENSITIVE_AUTOCOMPLETE, fix: 'autocomplete=off' };
    }
  }
  if (token && !VALID.has(token)) {
    return { blocked: true, reason: REASON.WEAK_AUTOCOMPLETE, fix: 'strip-token' };
  }
  if (req.crossSite && SECRET_TYPES.has(type) && autocomplete !== 'off') {
    return { blocked: true, reason: REASON.CROSS_SITE_LEAK, fix: 'autocomplete=off' };
  }
  if (type === 'one-time-code' && autocomplete !== 'one-time-code') {
    return { blocked: true, reason: REASON.MISSING_OFF, fix: 'autocomplete=one-time-code' };
  }
  return { blocked: false, reason: REASON.OK, fix: '' };
}

function applyAutocompletePolicyGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  let autocomplete = normalize(req.autocomplete);
  if (result.fix === 'autocomplete=off') autocomplete = 'off';
  if (result.fix === 'autocomplete=one-time-code') autocomplete = 'one-time-code';
  if (result.fix === 'strip-token') autocomplete = 'off';
  return {
    autocomplete,
    changed: autocomplete !== normalize(req.autocomplete),
    blocked: result.blocked && !result.fix,
    reason: result.reason,
  };
}

function auditAutocompleteBatch(fields, options) {
  const list = Array.isArray(fields) ? fields : [];
  const findings = [];
  let risky = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.reason !== REASON.OK) risky += 1;
    if (result.reason !== REASON.OK) findings.push({ name: item && item.name, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { risky, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no autocomplete risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyAutocompletePolicyGuard,
  auditAutocompleteBatch,
  describeFindings,
};
