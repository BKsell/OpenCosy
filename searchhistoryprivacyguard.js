'use strict';

const REASON = {
  SEARCH_STORE_RISK: 'search-store-risk',
  SEARCH_QUERY_TOO_LONG: 'search-query-too-long',
  SEARCH_QUERY_CONTROL: 'search-query-control',
  SEARCH_HISTORY_LIMIT: 'search-history-limit',
  SEARCH_HISTORY_DUPLICATE: 'search-history-duplicate',
};

const LIMITS = {
  MAX_QUERY: 256,
  MAX_HISTORY: 100,
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

function evaluateSearchHistoryPrivacyGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'storeQuery') === true) {
    add(REASON.SEARCH_STORE_RISK, '持久保存搜索词存在隐私风险', false);
  }

  if (text(pick(data, 'query')).length > 256) {
    add(REASON.SEARCH_QUERY_TOO_LONG, '搜索词长度超出上限', true);
  }

  if (/[\u0000-\u001f\u007f]/.test(text(pick(data, 'query')))) {
    add(REASON.SEARCH_QUERY_CONTROL, '搜索词包含控制字符', true);
  }

  const search_history_limitList = Array.isArray(pick(data, 'history')) ? pick(data, 'history') : [];
  if (search_history_limitList.length > 100) {
    add(REASON.SEARCH_HISTORY_LIMIT, '搜索历史条数超出上限', false);
  }

  const search_history_duplicateList = Array.isArray(pick(data, 'history')) ? pick(data, 'history') : [];
  const search_history_duplicateSeen = new Set();
  let search_history_duplicateDup = false;
  for (const item of search_history_duplicateList) {
    const marker = String((item) || '').toLowerCase();
    if (!marker) continue;
    if (search_history_duplicateSeen.has(marker)) search_history_duplicateDup = true;
    search_history_duplicateSeen.add(marker);
  }
  if (search_history_duplicateDup) {
    add(REASON.SEARCH_HISTORY_DUPLICATE, '搜索历史出现重复条目', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeSearchHistoryPrivacyGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateSearchHistoryPrivacyGuard, describeSearchHistoryPrivacyGuard };
