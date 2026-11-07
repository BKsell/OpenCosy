'use strict';

const REASON = {
  COEP_MISSING: 'coep-missing',
  COEP_INSECURE: 'coep-insecure',
  COEP_WILDCARD: 'coep-wildcard',
  COEP_REPORT_AGE: 'coep-report-age',
};

const LIMITS = {
  MAX_REPORT_AGE: 604800,
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

function evaluateCrossOriginEmbedderPolicyGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (!text(pick(data, 'headers.cross-origin-embedder-policy'))) {
    add(REASON.COEP_MISSING, '缺少 Cross-Origin-Embedder-Policy 响应头', true);
  }

  if (!['require-corp', 'credentialless'].includes(text(pick(data, 'headers.cross-origin-embedder-policy')).toLowerCase())) {
    add(REASON.COEP_INSECURE, 'COEP 取值不是 require-corp 或 credentialless', true);
  }

  if (new RegExp('\\*').test(text(pick(data, 'headers.cross-origin-embedder-policy')))) {
    add(REASON.COEP_WILDCARD, 'COEP 不允许通配符', true);
  }

  const coep_report_ageValue = Number(pick(data, 'headers.cross-origin-embedder-policy-report-age'));
  if (Number.isFinite(coep_report_ageValue) && (coep_report_ageValue < 0 || coep_report_ageValue > 604800)) {
    add(REASON.COEP_REPORT_AGE, 'COEP 报告缓存时间超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeCrossOriginEmbedderPolicyGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateCrossOriginEmbedderPolicyGuard, describeCrossOriginEmbedderPolicyGuard };
