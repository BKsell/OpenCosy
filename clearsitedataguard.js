'use strict';
const { describeReasonFrom } = require('./reasontext');

const { headerKey, headerText } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  UNKNOWN_TOKEN: 'unknown-token',
  WILDCARD: 'wildcard-clear',
  TOO_LONG: 'too-long',
  TOO_MANY: 'too-many',
};

const KNOWN_TOKENS = new Set([
  'cache',
  'cookies',
  'storage',
  'executioncontexts',
  '*',
]);

const MAX_VALUE_LENGTH = 256;
const MAX_TOKENS = 8;

function tokensOf(value) {
  return value
    .split(',')
    .map((part) => part.trim().replace(/^"|"$/g, '').trim())
    .filter(Boolean);
}

function inspectClearSiteData(headers) {
  const key = headerKey(headers, 'clear-site-data');
  if (!key) return { changed: false, reason: REASON.MISSING, removed: [], kept: [] };
  const text = headerText(headers, 'clear-site-data');
  if (text.length > MAX_VALUE_LENGTH) {
    return { changed: true, reason: REASON.TOO_LONG, removed: [], kept: [] };
  }
  const tokens = tokensOf(text);
  if (!tokens.length) {
    return { changed: true, reason: REASON.MALFORMED, removed: [], kept: [] };
  }
  if (tokens.length > MAX_TOKENS) {
    return { changed: true, reason: REASON.TOO_MANY, removed: tokens, kept: [] };
  }
  const removed = [];
  const kept = [];
  let wildcard = false;
  let needsRewrite = false;
  const canonical = tokens.map((token) => '"' + token.toLowerCase() + '"').join(', ');
  if (text.trim() !== canonical) needsRewrite = true;
  for (const token of tokens) {
    const lower = token.toLowerCase();
    if (KNOWN_TOKENS.has(lower)) {
      if (token !== lower) needsRewrite = true;
      kept.push(lower);
      if (lower === '*') wildcard = true;
      continue;
    }
    removed.push(lower);
    needsRewrite = true;
  }
  if (!removed.length) {
    if (wildcard) {
      return { changed: needsRewrite, reason: REASON.WILDCARD, removed, kept };
    }
    if (needsRewrite) {
      return { changed: true, reason: REASON.OK, removed, kept };
    }
    return { changed: false, reason: REASON.OK, removed, kept };
  }
  return {
    changed: true,
    reason: wildcard ? REASON.WILDCARD : REASON.UNKNOWN_TOKEN,
    removed,
    kept,
  };
}

function applyClearSiteDataGuard(headers) {
  const result = inspectClearSiteData(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, 'clear-site-data');
  if (!key) return result;
  if (!result.kept.length) {
    delete headers[key];
    return result;
  }
  const quoted = result.kept.map((token) => '"' + token + '"');
  delete headers[key];
  headers[key] = [quoted.join(', ')];
  return result;
}

function describeReason(reason) {
  return describeReasonFrom({
    [REASON.UNKNOWN_TOKEN]: 'Clear-Site-Data 含未知清理目标',
    [REASON.WILDCARD]: '站点一次性清除全部本地状态',
    [REASON.MALFORMED]: 'Clear-Site-Data 取值为空',
    [REASON.TOO_LONG]: 'Clear-Site-Data 取值超长',
    [REASON.TOO_MANY]: 'Clear-Site-Data 清理目标超过预算',
    [REASON.MISSING]: '响应未声明本地状态清理',
  }, reason, '本地状态清理目标合法');
}

module.exports = {
  REASON,
  KNOWN_TOKENS,
  MAX_VALUE_LENGTH,
  MAX_TOKENS,
  tokensOf,
  inspectClearSiteData,
  applyClearSiteDataGuard,
  describeReason,
};
