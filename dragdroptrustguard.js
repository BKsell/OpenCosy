'use strict';

const REASON = {
  DRAG_TYPE_UNKNOWN: 'drag-type-unknown',
  DRAG_EXTERNAL_RISK: 'drag-external-risk',
  DRAG_TYPE_LIMIT: 'drag-type-limit',
  DRAG_TYPE_EMPTY: 'drag-type-empty',
  DRAG_URL_NOT_HTTPS: 'drag-url-not-https',
};

const LIMITS = {
  MAX_TYPES: 4,
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

function evaluateDragDropTrustGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const drag_type_unknownList = Array.isArray(pick(data, 'types')) ? pick(data, 'types') : [];
  const drag_type_unknownHit = drag_type_unknownList.some((item) => !['text/plain', 'text/uri-list', 'image/png'].includes(String((item && typeof item === 'object' ? item : item) || '').toLowerCase()));
  if (drag_type_unknownHit) {
    add(REASON.DRAG_TYPE_UNKNOWN, '拖拽类型不在白名单', true);
  }

  if (pick(data, 'externalDrop') === true) {
    add(REASON.DRAG_EXTERNAL_RISK, '允许跨应用拖入会引入不可信内容', false);
  }

  const drag_type_limitList = Array.isArray(pick(data, 'types')) ? pick(data, 'types') : [];
  if (drag_type_limitList.length > 4) {
    add(REASON.DRAG_TYPE_LIMIT, '拖拽类型数量超出上限', false);
  }

  const drag_type_emptyList = Array.isArray(pick(data, 'types')) ? pick(data, 'types') : [];
  if (drag_type_emptyList.length === 0) {
    add(REASON.DRAG_TYPE_EMPTY, '拖拽类型列表为空', false);
  }

  if (new RegExp('^(?!https://).').test(text(pick(data, 'url')))) {
    add(REASON.DRAG_URL_NOT_HTTPS, '拖拽来源不是 HTTPS', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeDragDropTrustGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateDragDropTrustGuard, describeDragDropTrustGuard };
