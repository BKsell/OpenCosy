'use strict';

const REASON = {
  PRELOAD_RULES_MISSING: 'preload-rules-missing',
  PRELOAD_NOT_HTTPS: 'preload-not-https',
  PRELOAD_RULE_LIMIT: 'preload-rule-limit',
  PRELOAD_EMPTY_URL: 'preload-empty-url',
};

const LIMITS = {
  MAX_RULES: 12,
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

function evaluateSpeculativePreloadGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const preload_rules_missingList = Array.isArray(pick(data, 'rules')) ? pick(data, 'rules') : [];
  if (preload_rules_missingList.length === 0) {
    add(REASON.PRELOAD_RULES_MISSING, '启用推测预载但没有任何预载规则', false);
  }

  const preload_not_httpsList = Array.isArray(pick(data, 'rules')) ? pick(data, 'rules') : [];
  const preload_not_httpsHit = preload_not_httpsList.some((item) => new RegExp('^(?!https://).').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (preload_not_httpsHit) {
    add(REASON.PRELOAD_NOT_HTTPS, '预载目标不是 HTTPS', true);
  }

  const preload_rule_limitList = Array.isArray(pick(data, 'rules')) ? pick(data, 'rules') : [];
  if (preload_rule_limitList.length > 12) {
    add(REASON.PRELOAD_RULE_LIMIT, '预载规则数量超出上限', false);
  }

  const preload_empty_urlList = Array.isArray(pick(data, 'rules')) ? pick(data, 'rules') : [];
  if (preload_empty_urlList.some((item) => !String(item || '').trim())) {
    add(REASON.PRELOAD_EMPTY_URL, '预载规则存在空地址', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeSpeculativePreloadGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateSpeculativePreloadGuard, describeSpeculativePreloadGuard };
