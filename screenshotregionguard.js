'use strict';

const REASON = {
  SHOT_PATH_TRAVERSAL: 'shot-path-traversal',
  SHOT_FORMAT_UNKNOWN: 'shot-format-unknown',
  SHOT_QUALITY_RANGE: 'shot-quality-range',
  SHOT_CURSOR_RISK: 'shot-cursor-risk',
  SHOT_WIDTH_RANGE: 'shot-width-range',
};

const LIMITS = {
  MAX_QUALITY: 100,
  MAX_WIDTH: 8192,
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

function evaluateScreenshotRegionGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (text(pick(data, 'savePath')).includes('..')) {
    add(REASON.SHOT_PATH_TRAVERSAL, '截图保存路径包含穿越', true);
  }

  if (!['png', 'jpeg', 'webp'].includes(text(pick(data, 'format')).toLowerCase())) {
    add(REASON.SHOT_FORMAT_UNKNOWN, '截图格式不在白名单', true);
  }

  const shot_quality_rangeValue = Number(pick(data, 'quality'));
  if (Number.isFinite(shot_quality_rangeValue) && (shot_quality_rangeValue < 1 || shot_quality_rangeValue > 100)) {
    add(REASON.SHOT_QUALITY_RANGE, '截图质量超出区间', false);
  }

  if (pick(data, 'includeCursor') === true) {
    add(REASON.SHOT_CURSOR_RISK, '截图包含光标会泄露操作位置', false);
  }

  const shot_width_rangeValue = Number(pick(data, 'width'));
  if (Number.isFinite(shot_width_rangeValue) && (shot_width_rangeValue < 1 || shot_width_rangeValue > 8192)) {
    add(REASON.SHOT_WIDTH_RANGE, '截图宽度超出区间', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeScreenshotRegionGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateScreenshotRegionGuard, describeScreenshotRegionGuard };
