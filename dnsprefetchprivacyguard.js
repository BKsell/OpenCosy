'use strict';

const REASON = {
  DNS_PREFETCH_RISK: 'dns-prefetch-risk',
  DNS_HTTPS_ONLY_OFF: 'dns-https-only-off',
  DNS_HOST_WILDCARD: 'dns-host-wildcard',
  DNS_HOST_LIMIT: 'dns-host-limit',
  DNS_HOST_TRAVERSAL: 'dns-host-traversal',
};

const LIMITS = {
  MAX_HOSTS: 50,
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

function evaluateDnsPrefetchPrivacyGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'dnsPrefetch') === true) {
    add(REASON.DNS_PREFETCH_RISK, 'DNS 预取会提前暴露访问意图', false);
  }

  if (pick(data, 'httpsOnly') !== true) {
    add(REASON.DNS_HTTPS_ONLY_OFF, 'DNS 预取未限制 HTTPS', true);
  }

  const dns_host_wildcardList = Array.isArray(pick(data, 'hosts')) ? pick(data, 'hosts') : [];
  const dns_host_wildcardHit = dns_host_wildcardList.some((item) => new RegExp('\\*').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (dns_host_wildcardHit) {
    add(REASON.DNS_HOST_WILDCARD, 'DNS 预取白名单不允许通配', true);
  }

  const dns_host_limitList = Array.isArray(pick(data, 'hosts')) ? pick(data, 'hosts') : [];
  if (dns_host_limitList.length > 50) {
    add(REASON.DNS_HOST_LIMIT, 'DNS 预取白名单超出上限', false);
  }

  const dns_host_traversalList = Array.isArray(pick(data, 'hosts')) ? pick(data, 'hosts') : [];
  const dns_host_traversalHit = dns_host_traversalList.some((item) => new RegExp('\\.\\.|/|\\\\').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (dns_host_traversalHit) {
    add(REASON.DNS_HOST_TRAVERSAL, 'DNS 预取白名单包含路径字符', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeDnsPrefetchPrivacyGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateDnsPrefetchPrivacyGuard, describeDnsPrefetchPrivacyGuard };
