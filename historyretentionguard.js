'use strict';

const REASON = {
  HISTORY_DAYS_RANGE: 'history-days-range',
  HISTORY_INCOGNITO_PERSIST: 'history-incognito-persist',
  HISTORY_ENTRY_LIMIT: 'history-entry-limit',
};

const LIMITS = {
  MAX_DAYS: 365,
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

function evaluateHistoryRetentionGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const history_days_rangeValue = Number(pick(data, 'retentionDays'));
  if (Number.isFinite(history_days_rangeValue) && (history_days_rangeValue < 1 || history_days_rangeValue > 365)) {
    add(REASON.HISTORY_DAYS_RANGE, '历史保留天数超出区间', false);
  }

  if (pick(data, 'incognitoPersist') === true) {
    add(REASON.HISTORY_INCOGNITO_PERSIST, '无痕会话被持久化', true);
  }

  const history_entry_limitValue = Number(pick(data, 'maxEntries'));
  if (Number.isFinite(history_entry_limitValue) && (history_entry_limitValue < 0 || history_entry_limitValue > 100000)) {
    add(REASON.HISTORY_ENTRY_LIMIT, '历史条目上限超出配额', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeHistoryRetentionGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateHistoryRetentionGuard, describeHistoryRetentionGuard };
