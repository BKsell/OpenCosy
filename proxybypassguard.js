'use strict';

const REASON = {
  PROXY_NOT_HTTPS: 'proxy-not-https',
  PROXY_CREDENTIALS_IN_URL: 'proxy-credentials-in-url',
  PROXY_BYPASS_WILDCARD: 'proxy-bypass-wildcard',
  PROXY_BYPASS_LIMIT: 'proxy-bypass-limit',
  PROXY_BYPASS_EMPTY: 'proxy-bypass-empty',
};

const LIMITS = {
  MAX_BYPASS: 20,
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

function evaluateProxyBypassGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (new RegExp('^(?!https://).').test(text(pick(data, 'proxy')))) {
    add(REASON.PROXY_NOT_HTTPS, '代理地址不是 HTTPS', true);
  }

  if (new RegExp('://[^/@]+@').test(text(pick(data, 'proxy')))) {
    add(REASON.PROXY_CREDENTIALS_IN_URL, '代理地址内嵌凭据会被日志记录', true);
  }

  const proxy_bypass_wildcardList = Array.isArray(pick(data, 'bypass')) ? pick(data, 'bypass') : [];
  const proxy_bypass_wildcardHit = proxy_bypass_wildcardList.some((item) => new RegExp('\\*').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (proxy_bypass_wildcardHit) {
    add(REASON.PROXY_BYPASS_WILDCARD, '代理绕过列表不允许通配', true);
  }

  const proxy_bypass_limitList = Array.isArray(pick(data, 'bypass')) ? pick(data, 'bypass') : [];
  if (proxy_bypass_limitList.length > 20) {
    add(REASON.PROXY_BYPASS_LIMIT, '代理绕过条目超出上限', false);
  }

  const proxy_bypass_emptyList = Array.isArray(pick(data, 'bypass')) ? pick(data, 'bypass') : [];
  if (proxy_bypass_emptyList.length === 0) {
    add(REASON.PROXY_BYPASS_EMPTY, '代理绕过列表为空时全部走代理更安全', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeProxyBypassGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateProxyBypassGuard, describeProxyBypassGuard };
