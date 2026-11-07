'use strict';

const REASON = {
  ISOLATION_COOP_MISSING: 'isolation-coop-missing',
  ISOLATION_COEP_MISSING: 'isolation-coep-missing',
  ISOLATION_UNSAFE_COOP: 'isolation-unsafe-coop',
  ISOLATION_UNSAFE_COEP: 'isolation-unsafe-coep',
  ISOLATION_NOT_HTTPS: 'isolation-not-https',
  ISOLATION_MISMATCH: 'isolation-mismatch',
};

const LIMITS = {
  MAX_MISMATCH: 2,
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

function evaluateOriginIsolationGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (!text(pick(data, 'coop'))) {
    add(REASON.ISOLATION_COOP_MISSING, '跨源隔离缺少 COOP', true);
  }

  if (!text(pick(data, 'coep'))) {
    add(REASON.ISOLATION_COEP_MISSING, '跨源隔离缺少 COEP', true);
  }

  if (new RegExp('unsafe-none').test(text(pick(data, 'coop')))) {
    add(REASON.ISOLATION_UNSAFE_COOP, 'COOP 取值为 unsafe-none', true);
  }

  if (new RegExp('unsafe-none').test(text(pick(data, 'coep')))) {
    add(REASON.ISOLATION_UNSAFE_COEP, 'COEP 取值为 unsafe-none', true);
  }

  if (new RegExp('^(?!https://).').test(text(pick(data, 'url')))) {
    add(REASON.ISOLATION_NOT_HTTPS, '跨源隔离页面不是 HTTPS', true);
  }

  const isolation_mismatchValue = Number(pick(data, 'mismatchCount'));
  if (Number.isFinite(isolation_mismatchValue) && (isolation_mismatchValue < 0 || isolation_mismatchValue > 2)) {
    add(REASON.ISOLATION_MISMATCH, 'COOP/COEP 组合不一致的入口过多', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeOriginIsolationGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateOriginIsolationGuard, describeOriginIsolationGuard };
