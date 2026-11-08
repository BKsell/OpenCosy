'use strict';

const REASON = {
  CSPRO_MISSING: 'cspro-missing',
  CSPRO_UNSAFE_INLINE: 'cspro-unsafe-inline',
  CSPRO_ENDPOINT_NOT_HTTPS: 'cspro-endpoint-not-https',
  CSPRO_GROUP_MISMATCH: 'cspro-group-mismatch',
  CSPRO_ENDPOINT_LIMIT: 'cspro-endpoint-limit',
};

const LIMITS = {
  MAX_ENDPOINTS: 2,
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

function evaluateCspReportOnlyPolicyGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (!text(pick(data, 'headers.content-security-policy-report-only'))) {
    add(REASON.CSPRO_MISSING, '缺少仅报告模式的 CSP', false);
  }

  if (new RegExp('unsafe-inline').test(text(pick(data, 'headers.content-security-policy-report-only')))) {
    add(REASON.CSPRO_UNSAFE_INLINE, '仅报告 CSP 中仍使用 unsafe-inline', false);
  }

  if (new RegExp('^(?!https://).').test(text(pick(data, 'endpoint')))) {
    add(REASON.CSPRO_ENDPOINT_NOT_HTTPS, 'CSP 报告端点不是 HTTPS', true);
  }

  const capture = new RegExp('report-to\\s+(\\w+)').exec(text(pick(data, 'headers.content-security-policy-report-only')));
  if (capture && capture[1] && capture[1] !== text(pick(data, 'reportTo'))) {
    add(REASON.CSPRO_GROUP_MISMATCH, 'CSP 报告组与 report-to 名称不一致', false);
  }

  const cspro_endpoint_limitValue = Number(pick(data, 'endpointCount'));
  if (Number.isFinite(cspro_endpoint_limitValue) && (cspro_endpoint_limitValue < 0 || cspro_endpoint_limitValue > 2)) {
    add(REASON.CSPRO_ENDPOINT_LIMIT, '报告端点数量超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeCspReportOnlyPolicyGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateCspReportOnlyPolicyGuard, describeCspReportOnlyPolicyGuard };
