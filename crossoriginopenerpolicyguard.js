'use strict';

const REASON = {
  COOP_MISSING: 'coop-missing',
  COOP_UNSAFE: 'coop-unsafe',
  COOP_ALLOW_POPUPS: 'coop-allow-popups',
  COOP_POPUPS_LIMIT: 'coop-popups-limit',
};

const LIMITS = {
  MAX_POPUPS: 3,
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

function evaluateCrossOriginOpenerPolicyGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (!text(pick(data, 'headers.cross-origin-opener-policy'))) {
    add(REASON.COOP_MISSING, '缺少 Cross-Origin-Opener-Policy 响应头', true);
  }

  if (!['same-origin', 'same-origin-allow-popups', 'noopener-allow-popups'].includes(text(pick(data, 'headers.cross-origin-opener-policy')).toLowerCase())) {
    add(REASON.COOP_UNSAFE, 'COOP 为 unsafe-none 会放弃进程隔离', true);
  }

  if (new RegExp('allow-popups').test(text(pick(data, 'headers.cross-origin-opener-policy')))) {
    add(REASON.COOP_ALLOW_POPUPS, 'same-origin-allow-popups 需要额外审查', false);
  }

  const coop_popups_limitValue = Number(pick(data, 'headers.cross-origin-opener-policy-popup-count'));
  if (Number.isFinite(coop_popups_limitValue) && (coop_popups_limitValue < 0 || coop_popups_limitValue > 3)) {
    add(REASON.COOP_POPUPS_LIMIT, '允许的弹出窗口数量超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeCrossOriginOpenerPolicyGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateCrossOriginOpenerPolicyGuard, describeCrossOriginOpenerPolicyGuard };
