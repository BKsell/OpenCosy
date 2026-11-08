'use strict';

const REASON = {
  REVEAL_ENABLED_RISK: 'reveal-enabled-risk',
  REVEAL_SECONDS_RANGE: 'reveal-seconds-range',
  REVEAL_SITE_LIMIT: 'reveal-site-limit',
};

const LIMITS = {
  MAX_SECONDS: 30,
  MAX_SITES: 50,
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

function evaluatePasswordRevealGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'revealEnabled') === true) {
    add(REASON.REVEAL_ENABLED_RISK, '默认允许明文显示密码', true);
  }

  const reveal_seconds_rangeValue = Number(pick(data, 'revealSeconds'));
  if (Number.isFinite(reveal_seconds_rangeValue) && (reveal_seconds_rangeValue < 1 || reveal_seconds_rangeValue > 30)) {
    add(REASON.REVEAL_SECONDS_RANGE, '密码明文显示时长超出区间', false);
  }

  const reveal_site_limitValue = Number(pick(data, 'perSitePermissions'));
  if (Number.isFinite(reveal_site_limitValue) && (reveal_site_limitValue < 0 || reveal_site_limitValue > 50)) {
    add(REASON.REVEAL_SITE_LIMIT, '按站点明文权限数量超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describePasswordRevealGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluatePasswordRevealGuard, describePasswordRevealGuard };
