'use strict';

const REASON = {
  REFERRER_POLICY_UNKNOWN: 'referrer-policy-unknown',
  REFERRER_UPGRADE_DOWNGRADE: 'referrer-upgrade-downgrade',
  REFERRER_FULL_CROSS_ORIGIN: 'referrer-full-cross-origin',
  REFERRER_POLICY_TOO_LONG: 'referrer-policy-too-long',
};

const LIMITS = {
  MAX_POLICY: 64,
};

function pick(source, path) {
  let current = source;
  for (const part of path.split('.')) {
    if (!current || typeof current !== 'object') return undefined;
    current = current[part];
  }
  return current;
}

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function evaluateReferrerLeakPolicyGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (!['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'origin-when-cross-origin'].includes(text(pick(data, 'policy')).toLowerCase())) {
    add(REASON.REFERRER_POLICY_UNKNOWN, 'Referrer-Policy 取值不在白名单', true);
  }

  if (pick(data, 'downgrade') === true) {
    add(REASON.REFERRER_UPGRADE_DOWNGRADE, '允许 HTTPS 向 HTTP 传递来源', true);
  }

  if (pick(data, 'trimCrossOrigin') !== true) {
    add(REASON.REFERRER_FULL_CROSS_ORIGIN, '跨源仍发送完整来源', false);
  }

  if (text(pick(data, 'policy')).length > 64) {
    add(REASON.REFERRER_POLICY_TOO_LONG, 'Referrer-Policy 取值过长', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeReferrerLeakPolicyGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateReferrerLeakPolicyGuard, describeReferrerLeakPolicyGuard };
