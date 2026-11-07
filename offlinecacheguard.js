'use strict';

const REASON = {
  CACHE_URL_NOT_HTTPS: 'cache-url-not-https',
  CACHE_ENTRY_NOT_HTTPS: 'cache-entry-not-https',
  CACHE_TTL_RANGE: 'cache-ttl-range',
  CACHE_ENTRY_LIMIT: 'cache-entry-limit',
  CACHE_SIZE_LIMIT: 'cache-size-limit',
  CACHE_ENTRY_EMPTY_URL: 'cache-entry-empty-url',
};

const LIMITS = {
  MAX_ENTRIES: 500,
  MAX_BYTES: 67108864,
  MAX_TTL: 604800,
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

function evaluateOfflineCacheGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (new RegExp('^(?!https://).').test(text(pick(data, 'url')))) {
    add(REASON.CACHE_URL_NOT_HTTPS, '离线缓存页面不是 HTTPS', true);
  }

  const cache_entry_not_httpsList = Array.isArray(pick(data, 'entries')) ? pick(data, 'entries') : [];
  const cache_entry_not_httpsHit = cache_entry_not_httpsList.some((item) => new RegExp('^(?!https://).').test(String((item && typeof item === 'object' ? item.url : item) || '')));
  if (cache_entry_not_httpsHit) {
    add(REASON.CACHE_ENTRY_NOT_HTTPS, '缓存条目地址不是 HTTPS', true);
  }

  const cache_ttl_rangeList = Array.isArray(pick(data, 'entries')) ? pick(data, 'entries') : [];
  const cache_ttl_rangeHit = cache_ttl_rangeList.some((item) => {
    const value = Number(item && typeof item === 'object' ? item.ttl : item);
    return Number.isFinite(value) && (value < 0 || value > 604800);
  });
  if (cache_ttl_rangeHit) {
    add(REASON.CACHE_TTL_RANGE, '缓存 TTL 超出区间', false);
  }

  const cache_entry_limitList = Array.isArray(pick(data, 'entries')) ? pick(data, 'entries') : [];
  if (cache_entry_limitList.length > 500) {
    add(REASON.CACHE_ENTRY_LIMIT, '缓存条目数量超出上限', false);
  }

  const cache_size_limitValue = Number(pick(data, 'maxBytes'));
  if (Number.isFinite(cache_size_limitValue) && (cache_size_limitValue < 0 || cache_size_limitValue > 67108864)) {
    add(REASON.CACHE_SIZE_LIMIT, '缓存体积上限超出配额', false);
  }

  const cache_entry_empty_urlList = Array.isArray(pick(data, 'entries')) ? pick(data, 'entries') : [];
  if (cache_entry_empty_urlList.some((item) => !String(item || '').trim())) {
    add(REASON.CACHE_ENTRY_EMPTY_URL, '缓存条目地址为空', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeOfflineCacheGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateOfflineCacheGuard, describeOfflineCacheGuard };
