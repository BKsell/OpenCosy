'use strict';

const REASON = {
  LOCK_IDLE_RANGE: 'lock-idle-range',
  LOCK_UNLOCK_UNKNOWN: 'lock-unlock-unknown',
  LOCK_DISABLED: 'lock-disabled',
  LOCK_MINIMIZE_OFF: 'lock-minimize-off',
};

const LIMITS = {
  MIN_IDLE: 1,
  MAX_IDLE: 120,
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

function evaluateSessionLockGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const lock_idle_rangeValue = Number(pick(data, 'idleMinutes'));
  if (Number.isFinite(lock_idle_rangeValue) && (lock_idle_rangeValue < 1 || lock_idle_rangeValue > 120)) {
    add(REASON.LOCK_IDLE_RANGE, '自动锁定空闲时间超出区间', false);
  }

  if (!['password', 'biometric'].includes(text(pick(data, 'unlock')).toLowerCase())) {
    add(REASON.LOCK_UNLOCK_UNKNOWN, '解锁方式不在白名单', true);
  }

  if (pick(data, 'enabled') !== true) {
    add(REASON.LOCK_DISABLED, '会话自动锁定未启用', false);
  }

  if (pick(data, 'lockOnMinimize') !== true) {
    add(REASON.LOCK_MINIMIZE_OFF, '最小化后不锁定会暴露会话', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeSessionLockGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateSessionLockGuard, describeSessionLockGuard };
