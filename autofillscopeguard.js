'use strict';

const REASON = {
  AUTOFILL_CATEGORY_UNKNOWN: 'autofill-category-unknown',
  AUTOFILL_CROSS_SITE: 'autofill-cross-site',
  AUTOFILL_CATEGORY_LIMIT: 'autofill-category-limit',
  AUTOFILL_CATEGORY_EMPTY: 'autofill-category-empty',
};

const LIMITS = {
  MAX_CATEGORIES: 4,
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

function evaluateAutofillScopeGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const autofill_category_unknownList = Array.isArray(pick(data, 'categories')) ? pick(data, 'categories') : [];
  const autofill_category_unknownHit = autofill_category_unknownList.some((item) => !['address', 'creditcard', 'email', 'phone'].includes(String((item && typeof item === 'object' ? item : item) || '').toLowerCase()));
  if (autofill_category_unknownHit) {
    add(REASON.AUTOFILL_CATEGORY_UNKNOWN, '自动填充类别不在白名单', true);
  }

  if (pick(data, 'crossSite') === true) {
    add(REASON.AUTOFILL_CROSS_SITE, '跨站自动填充会泄露表单数据', true);
  }

  const autofill_category_limitList = Array.isArray(pick(data, 'categories')) ? pick(data, 'categories') : [];
  if (autofill_category_limitList.length > 4) {
    add(REASON.AUTOFILL_CATEGORY_LIMIT, '自动填充类别数量超出上限', false);
  }

  const autofill_category_emptyList = Array.isArray(pick(data, 'categories')) ? pick(data, 'categories') : [];
  if (autofill_category_emptyList.length === 0) {
    add(REASON.AUTOFILL_CATEGORY_EMPTY, '自动填充类别为空', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeAutofillScopeGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateAutofillScopeGuard, describeAutofillScopeGuard };
