'use strict';

const REASON = {
  PP_REPORT_MISSING: 'pp-report-missing',
  PP_ENDPOINT_NOT_HTTPS: 'pp-endpoint-not-https',
  PP_ENDPOINT_CREDENTIALS: 'pp-endpoint-credentials',
  PP_GROUP_LIMIT: 'pp-group-limit',
  PP_DUPLICATE_GROUP: 'pp-duplicate-group',
};

const LIMITS = {
  MAX_GROUPS: 4,
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

function evaluatePermissionPolicyReportGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (!text(pick(data, 'reportTo'))) {
    add(REASON.PP_REPORT_MISSING, 'Permissions-Policy 缺少报告组', false);
  }

  if (new RegExp('^(?!https://).').test(text(pick(data, 'endpoint')))) {
    add(REASON.PP_ENDPOINT_NOT_HTTPS, '报告端点不是 HTTPS', true);
  }

  if (new RegExp('://[^/@]+@').test(text(pick(data, 'endpoint')))) {
    add(REASON.PP_ENDPOINT_CREDENTIALS, '报告端点不允许携带凭据', true);
  }

  const pp_group_limitValue = Number(pick(data, 'groupCount'));
  if (Number.isFinite(pp_group_limitValue) && (pp_group_limitValue < 0 || pp_group_limitValue > 4)) {
    add(REASON.PP_GROUP_LIMIT, '报告组数量超出上限', false);
  }

  const pp_duplicate_groupList = Array.isArray(pick(data, 'groups')) ? pick(data, 'groups') : [];
  const pp_duplicate_groupSeen = new Set();
  let pp_duplicate_groupDup = false;
  for (const item of pp_duplicate_groupList) {
    const marker = String((item) || '').toLowerCase();
    if (!marker) continue;
    if (pp_duplicate_groupSeen.has(marker)) pp_duplicate_groupDup = true;
    pp_duplicate_groupSeen.add(marker);
  }
  if (pp_duplicate_groupDup) {
    add(REASON.PP_DUPLICATE_GROUP, '报告组重复声明', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describePermissionPolicyReportGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluatePermissionPolicyReportGuard, describePermissionPolicyReportGuard };
