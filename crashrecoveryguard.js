'use strict';

const REASON = {
  CRASH_UPLOAD_RISK: 'crash-upload-risk',
  CRASH_ENDPOINT_NOT_HTTPS: 'crash-endpoint-not-https',
  CRASH_RETENTION_RANGE: 'crash-retention-range',
  CRASH_ENDPOINT_CREDENTIALS: 'crash-endpoint-credentials',
};

const LIMITS = {
  MAX_DAYS: 30,
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

function evaluateCrashRecoveryGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'uploadReports') === true) {
    add(REASON.CRASH_UPLOAD_RISK, '默认上传崩溃报告存在隐私风险', false);
  }

  if (new RegExp('^(?!https://).').test(text(pick(data, 'endpoint')))) {
    add(REASON.CRASH_ENDPOINT_NOT_HTTPS, '崩溃报告端点不是 HTTPS', true);
  }

  const crash_retention_rangeValue = Number(pick(data, 'retentionDays'));
  if (Number.isFinite(crash_retention_rangeValue) && (crash_retention_rangeValue < 1 || crash_retention_rangeValue > 30)) {
    add(REASON.CRASH_RETENTION_RANGE, '崩溃记录保留天数超出区间', false);
  }

  if (new RegExp('://[^/@]+@').test(text(pick(data, 'endpoint')))) {
    add(REASON.CRASH_ENDPOINT_CREDENTIALS, '崩溃报告端点不允许内嵌凭据', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeCrashRecoveryGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateCrashRecoveryGuard, describeCrashRecoveryGuard };
