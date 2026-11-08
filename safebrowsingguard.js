'use strict';

const REASON = {
  SAFE_PROVIDER_UNKNOWN: 'safe-provider-unknown',
  SAFE_INTERVAL_RANGE: 'safe-interval-range',
  SAFE_ENDPOINT_NOT_HTTPS: 'safe-endpoint-not-https',
  SAFE_DISABLED: 'safe-disabled',
};

const LIMITS = {
  MIN_INTERVAL: 1,
  MAX_INTERVAL: 24,
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

function evaluateSafeBrowsingGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (!['local', 'remote'].includes(text(pick(data, 'provider')).toLowerCase())) {
    add(REASON.SAFE_PROVIDER_UNKNOWN, '安全浏览提供方不在白名单', true);
  }

  const safe_interval_rangeValue = Number(pick(data, 'updateIntervalHours'));
  if (Number.isFinite(safe_interval_rangeValue) && (safe_interval_rangeValue < 1 || safe_interval_rangeValue > 24)) {
    add(REASON.SAFE_INTERVAL_RANGE, '安全浏览更新间隔超出区间', false);
  }

  if (new RegExp('^(?!https://).').test(text(pick(data, 'endpoint')))) {
    add(REASON.SAFE_ENDPOINT_NOT_HTTPS, '安全浏览更新端点不是 HTTPS', true);
  }

  if (pick(data, 'enabled') !== true) {
    add(REASON.SAFE_DISABLED, '安全浏览未启用', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeSafeBrowsingGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateSafeBrowsingGuard, describeSafeBrowsingGuard };
