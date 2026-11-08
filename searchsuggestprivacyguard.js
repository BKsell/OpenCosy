'use strict';

const REASON = {
  SUGGEST_ENDPOINT_NOT_HTTPS: 'suggest-endpoint-not-https',
  SUGGEST_ENDPOINT_CREDENTIALS: 'suggest-endpoint-credentials',
  SUGGEST_LEAK_RISK: 'suggest-leak-risk',
  SUGGEST_HOST_LIMIT: 'suggest-host-limit',
};

const LIMITS = {
  MAX_HOSTS: 3,
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

function evaluateSearchSuggestPrivacyGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (new RegExp('^(?!https://).').test(text(pick(data, 'endpoint')))) {
    add(REASON.SUGGEST_ENDPOINT_NOT_HTTPS, '搜索建议端点不是 HTTPS', true);
  }

  if (new RegExp('://[^/@]+@').test(text(pick(data, 'endpoint')))) {
    add(REASON.SUGGEST_ENDPOINT_CREDENTIALS, '搜索建议端点内嵌凭据', true);
  }

  if (pick(data, 'leakQuery') === true) {
    add(REASON.SUGGEST_LEAK_RISK, '输入即上传搜索词会泄露草稿', false);
  }

  const suggest_host_limitList = Array.isArray(pick(data, 'hosts')) ? pick(data, 'hosts') : [];
  if (suggest_host_limitList.length > 3) {
    add(REASON.SUGGEST_HOST_LIMIT, '搜索建议白名单超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeSearchSuggestPrivacyGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateSearchSuggestPrivacyGuard, describeSearchSuggestPrivacyGuard };
