'use strict';

const REASON = {
  HINT_ACCEPT_CH_MISSING: 'hint-accept-ch-missing',
  HINT_HIGH_ENTROPY: 'hint-high-entropy',
  HINT_WILDCARD: 'hint-wildcard',
  HINT_COUNT: 'hint-count',
  HINT_NOT_HTTPS: 'hint-not-https',
};

const LIMITS = {
  MAX_HINTS: 5,
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

function evaluateClientHintMinimizerGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (!text(pick(data, 'headers.accept-ch'))) {
    add(REASON.HINT_ACCEPT_CH_MISSING, '缺少 Accept-CH 声明', false);
  }

  if (new RegExp('sec-ch-ua-full-version').test(text(pick(data, 'headers.accept-ch')))) {
    add(REASON.HINT_HIGH_ENTROPY, '请求了高熵客户端提示', false);
  }

  if (new RegExp('\\*').test(text(pick(data, 'headers.accept-ch')))) {
    add(REASON.HINT_WILDCARD, 'Accept-CH 不允许通配符', true);
  }

  const hint_countValue = Number(pick(data, 'hintCount'));
  if (Number.isFinite(hint_countValue) && (hint_countValue < 0 || hint_countValue > 5)) {
    add(REASON.HINT_COUNT, '客户端提示数量超出上限', false);
  }

  if (new RegExp('^(?!https://).').test(text(pick(data, 'url')))) {
    add(REASON.HINT_NOT_HTTPS, '客户端提示仅应在 HTTPS 下启用', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeClientHintMinimizerGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateClientHintMinimizerGuard, describeClientHintMinimizerGuard };
