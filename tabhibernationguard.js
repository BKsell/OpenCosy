'use strict';

const REASON = {
  HIBERNATE_TIMEOUT_RANGE: 'hibernate-timeout-range',
  HIBERNATE_LIMIT_RANGE: 'hibernate-limit-range',
  HIBERNATE_AGGRESSIVE_RISK: 'hibernate-aggressive-risk',
  HIBERNATE_EXEMPT_WILDCARD: 'hibernate-exempt-wildcard',
  HIBERNATE_EXEMPT_LIMIT: 'hibernate-exempt-limit',
};

const LIMITS = {
  MIN_TIMEOUT: 5,
  MAX_TIMEOUT: 240,
  MAX_HIBERNATED: 200,
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

function evaluateTabHibernationGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const hibernate_timeout_rangeValue = Number(pick(data, 'timeoutMinutes'));
  if (Number.isFinite(hibernate_timeout_rangeValue) && (hibernate_timeout_rangeValue < 5 || hibernate_timeout_rangeValue > 240)) {
    add(REASON.HIBERNATE_TIMEOUT_RANGE, '休眠超时超出区间', false);
  }

  const hibernate_limit_rangeValue = Number(pick(data, 'maxHibernated'));
  if (Number.isFinite(hibernate_limit_rangeValue) && (hibernate_limit_rangeValue < 0 || hibernate_limit_rangeValue > 200)) {
    add(REASON.HIBERNATE_LIMIT_RANGE, '休眠标签页上限超出区间', false);
  }

  if (pick(data, 'aggressive') === true) {
    add(REASON.HIBERNATE_AGGRESSIVE_RISK, '激进休眠会丢失页面状态', false);
  }

  const hibernate_exempt_wildcardList = Array.isArray(pick(data, 'exemptHosts')) ? pick(data, 'exemptHosts') : [];
  const hibernate_exempt_wildcardHit = hibernate_exempt_wildcardList.some((item) => new RegExp('\\*').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (hibernate_exempt_wildcardHit) {
    add(REASON.HIBERNATE_EXEMPT_WILDCARD, '休眠豁免主机不允许通配', true);
  }

  const hibernate_exempt_limitList = Array.isArray(pick(data, 'exemptHosts')) ? pick(data, 'exemptHosts') : [];
  if (hibernate_exempt_limitList.length > 100) {
    add(REASON.HIBERNATE_EXEMPT_LIMIT, '休眠豁免名单超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeTabHibernationGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateTabHibernationGuard, describeTabHibernationGuard };
