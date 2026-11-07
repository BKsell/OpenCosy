'use strict';

const REASON = {
  HINTS_MISSING: 'hints-missing',
  HINTS_NOT_HTTPS: 'hints-not-https',
  HINTS_WILDCARD: 'hints-wildcard',
  HINTS_COUNT: 'hints-count',
};

const LIMITS = {
  MAX_HINTS: 6,
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

function evaluateEarlyHintsGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (!text(pick(data, 'headers.link'))) {
    add(REASON.HINTS_MISSING, '缺少 103 Early Hints 预载链接', false);
  }

  if (new RegExp('<http://').test(text(pick(data, 'headers.link')))) {
    add(REASON.HINTS_NOT_HTTPS, 'Early Hints 预载目标不是 HTTPS', true);
  }

  if (new RegExp('<https://\\*').test(text(pick(data, 'headers.link')))) {
    add(REASON.HINTS_WILDCARD, 'Early Hints 出现通配源', true);
  }

  const hints_countValue = Number(pick(data, 'hintCount'));
  if (Number.isFinite(hints_countValue) && (hints_countValue < 0 || hints_countValue > 6)) {
    add(REASON.HINTS_COUNT, 'Early Hints 链接数量超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeEarlyHintsGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateEarlyHintsGuard, describeEarlyHintsGuard };
