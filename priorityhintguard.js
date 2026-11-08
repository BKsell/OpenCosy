'use strict';

const REASON = {
  PRIORITY_INVALID: 'priority-invalid',
  PRIORITY_NOT_HTTPS: 'priority-not-https',
  PRIORITY_DUPLICATE: 'priority-duplicate',
};

const LIMITS = {
  MAX_RESOURCES: 8,
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

function evaluatePriorityHintGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (new RegExp('[^uifbUIFB=0-9,\\s()]').test(text(pick(data, 'headers.priority')))) {
    add(REASON.PRIORITY_INVALID, 'Priority 头取值非法', false);
  }

  const priority_not_httpsList = Array.isArray(pick(data, 'resources')) ? pick(data, 'resources') : [];
  const priority_not_httpsHit = priority_not_httpsList.some((item) => new RegExp('^(?!https://).').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (priority_not_httpsHit) {
    add(REASON.PRIORITY_NOT_HTTPS, '优先级提示资源不是 HTTPS', true);
  }

  const priority_duplicateList = Array.isArray(pick(data, 'resources')) ? pick(data, 'resources') : [];
  const priority_duplicateSeen = new Set();
  let priority_duplicateDup = false;
  for (const item of priority_duplicateList) {
    const marker = String((item) || '').toLowerCase();
    if (!marker) continue;
    if (priority_duplicateSeen.has(marker)) priority_duplicateDup = true;
    priority_duplicateSeen.add(marker);
  }
  if (priority_duplicateDup) {
    add(REASON.PRIORITY_DUPLICATE, '优先级资源重复声明', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describePriorityHintGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluatePriorityHintGuard, describePriorityHintGuard };
