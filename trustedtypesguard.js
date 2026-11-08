'use strict';

const REASON = {
  TT_MISSING_FOR: 'tt-missing-for',
  TT_MISSING_POLICIES: 'tt-missing-policies',
  TT_WILDCARD: 'tt-wildcard',
  TT_POLICY_LIMIT: 'tt-policy-limit',
};

const LIMITS = {
  MAX_POLICIES: 4,
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

function evaluateTrustedTypesGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (new RegExp('^(?!.*require-trusted-types-for)').test(text(pick(data, 'headers.content-security-policy')))) {
    add(REASON.TT_MISSING_FOR, 'CSP 缺少 require-trusted-types-for 指令', true);
  }

  if (new RegExp('^(?!.*trusted-types)').test(text(pick(data, 'headers.content-security-policy')))) {
    add(REASON.TT_MISSING_POLICIES, 'CSP 缺少 trusted-types 白名单', false);
  }

  if (new RegExp("trusted-types[^;]*'?\\*").test(text(pick(data, 'headers.content-security-policy')))) {
    add(REASON.TT_WILDCARD, 'trusted-types 不能使用通配符', true);
  }

  const tt_policy_limitValue = Number(pick(data, 'policyCount'));
  if (Number.isFinite(tt_policy_limitValue) && (tt_policy_limitValue < 0 || tt_policy_limitValue > 4)) {
    add(REASON.TT_POLICY_LIMIT, '可信类型策略数量超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeTrustedTypesGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateTrustedTypesGuard, describeTrustedTypesGuard };
