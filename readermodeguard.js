'use strict';

const REASON = {
  READER_AUTO_RISK: 'reader-auto-risk',
  READER_HOST_WILDCARD: 'reader-host-wildcard',
  READER_HOST_TRAVERSAL: 'reader-host-traversal',
  READER_HOST_LIMIT: 'reader-host-limit',
  READER_WIDTH_RANGE: 'reader-width-range',
};

const LIMITS = {
  MAX_HOSTS: 100,
  MAX_WIDTH: 1200,
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

function evaluateReaderModeGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'autoEnable') === true) {
    add(REASON.READER_AUTO_RISK, '全站自动进入阅读模式存在钓鱼风险', false);
  }

  const reader_host_wildcardList = Array.isArray(pick(data, 'hosts')) ? pick(data, 'hosts') : [];
  const reader_host_wildcardHit = reader_host_wildcardList.some((item) => new RegExp('\\*').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (reader_host_wildcardHit) {
    add(REASON.READER_HOST_WILDCARD, '阅读模式主机白名单不允许通配', true);
  }

  const reader_host_traversalList = Array.isArray(pick(data, 'hosts')) ? pick(data, 'hosts') : [];
  const reader_host_traversalHit = reader_host_traversalList.some((item) => new RegExp('\\.\\.|/|\\\\').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (reader_host_traversalHit) {
    add(REASON.READER_HOST_TRAVERSAL, '阅读模式主机白名单包含路径字符', true);
  }

  const reader_host_limitList = Array.isArray(pick(data, 'hosts')) ? pick(data, 'hosts') : [];
  if (reader_host_limitList.length > 100) {
    add(REASON.READER_HOST_LIMIT, '阅读模式白名单数量超出上限', false);
  }

  const reader_width_rangeValue = Number(pick(data, 'maxWidth'));
  if (Number.isFinite(reader_width_rangeValue) && (reader_width_rangeValue < 320 || reader_width_rangeValue > 1200)) {
    add(REASON.READER_WIDTH_RANGE, '阅读模式正文宽度超出区间', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeReaderModeGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateReaderModeGuard, describeReaderModeGuard };
