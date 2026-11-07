'use strict';

const REASON = {
  BOOKMARK_SOURCE_TRAVERSAL: 'bookmark-source-traversal',
  BOOKMARK_URL_NOT_HTTPS: 'bookmark-url-not-https',
  BOOKMARK_DUPLICATE: 'bookmark-duplicate',
  BOOKMARK_LIMIT: 'bookmark-limit',
  BOOKMARK_EMPTY: 'bookmark-empty',
  BOOKMARK_URL_EMPTY: 'bookmark-url-empty',
};

const LIMITS = {
  MAX_BOOKMARKS: 5000,
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

function evaluateBookmarkImportGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (text(pick(data, 'sourcePath')).includes('..')) {
    add(REASON.BOOKMARK_SOURCE_TRAVERSAL, '书签导入源路径包含穿越', true);
  }

  const bookmark_url_not_httpsList = Array.isArray(pick(data, 'bookmarks')) ? pick(data, 'bookmarks') : [];
  const bookmark_url_not_httpsHit = bookmark_url_not_httpsList.some((item) => new RegExp('^(?!https://).').test(String((item && typeof item === 'object' ? item.url : item) || '')));
  if (bookmark_url_not_httpsHit) {
    add(REASON.BOOKMARK_URL_NOT_HTTPS, '导入书签地址不是 HTTPS', false);
  }

  const bookmark_duplicateList = Array.isArray(pick(data, 'bookmarks')) ? pick(data, 'bookmarks') : [];
  const bookmark_duplicateSeen = new Set();
  let bookmark_duplicateDup = false;
  for (const item of bookmark_duplicateList) {
    const marker = String((item && typeof item === 'object' ? item.url : item) || '').toLowerCase();
    if (!marker) continue;
    if (bookmark_duplicateSeen.has(marker)) bookmark_duplicateDup = true;
    bookmark_duplicateSeen.add(marker);
  }
  if (bookmark_duplicateDup) {
    add(REASON.BOOKMARK_DUPLICATE, '导入书签出现重复地址', false);
  }

  const bookmark_limitList = Array.isArray(pick(data, 'bookmarks')) ? pick(data, 'bookmarks') : [];
  if (bookmark_limitList.length > 5000) {
    add(REASON.BOOKMARK_LIMIT, '导入书签数量超出上限', false);
  }

  const bookmark_emptyList = Array.isArray(pick(data, 'bookmarks')) ? pick(data, 'bookmarks') : [];
  if (bookmark_emptyList.length === 0) {
    add(REASON.BOOKMARK_EMPTY, '导入书签列表为空', false);
  }

  const bookmark_url_emptyList = Array.isArray(pick(data, 'bookmarks')) ? pick(data, 'bookmarks') : [];
  if (bookmark_url_emptyList.some((item) => !String(item || '').trim())) {
    add(REASON.BOOKMARK_URL_EMPTY, '导入书签地址为空', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeBookmarkImportGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateBookmarkImportGuard, describeBookmarkImportGuard };
