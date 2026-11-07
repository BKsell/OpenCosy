'use strict';

const REASON = {
  QUIET_HOUR_RANGE: 'quiet-hour-range',
  QUIET_HOUR_END_RANGE: 'quiet-hour-end-range',
  QUIET_OVERRIDE_RISK: 'quiet-override-risk',
  QUIET_DISABLED: 'quiet-disabled',
};

const LIMITS = {
  MIN_HOUR: 0,
  MAX_HOUR: 23,
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

function evaluateNotificationQuietGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const quiet_hour_rangeValue = Number(pick(data, 'startHour'));
  if (Number.isFinite(quiet_hour_rangeValue) && (quiet_hour_rangeValue < 0 || quiet_hour_rangeValue > 23)) {
    add(REASON.QUIET_HOUR_RANGE, '免打扰时段超出 0-23', false);
  }

  const quiet_hour_end_rangeValue = Number(pick(data, 'endHour'));
  if (Number.isFinite(quiet_hour_end_rangeValue) && (quiet_hour_end_rangeValue < 0 || quiet_hour_end_rangeValue > 23)) {
    add(REASON.QUIET_HOUR_END_RANGE, '免打扰结束时段超出 0-23', false);
  }

  if (pick(data, 'overrideDnd') === true) {
    add(REASON.QUIET_OVERRIDE_RISK, '允许绕过系统勿扰模式', false);
  }

  if (pick(data, 'enabled') !== true) {
    add(REASON.QUIET_DISABLED, '免打扰未启用', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeNotificationQuietGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateNotificationQuietGuard, describeNotificationQuietGuard };
