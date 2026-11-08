'use strict';

const REASON = {
  PASTE_STRIP_OFF: 'paste-strip-off',
  PASTE_IMAGE_RISK: 'paste-image-risk',
  PASTE_MIME_UNKNOWN: 'paste-mime-unknown',
  PASTE_LENGTH_RANGE: 'paste-length-range',
  PASTE_MIME_EMPTY: 'paste-mime-empty',
};

const LIMITS = {
  MIN_STRIP: 1,
  MAX_LENGTH: 1048576,
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

function evaluatePasteInSanitizerGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'stripOff') === true) {
    add(REASON.PASTE_STRIP_OFF, '粘贴未剥离富文本标记', true);
  }

  if (pick(data, 'allowImages') === true) {
    add(REASON.PASTE_IMAGE_RISK, '允许粘贴图片会引入外部资源', false);
  }

  const paste_mime_unknownList = Array.isArray(pick(data, 'mimes')) ? pick(data, 'mimes') : [];
  const paste_mime_unknownHit = paste_mime_unknownList.some((item) => !['text/plain', 'text/html'].includes(String((item && typeof item === 'object' ? item : item) || '').toLowerCase()));
  if (paste_mime_unknownHit) {
    add(REASON.PASTE_MIME_UNKNOWN, '粘贴 MIME 不在白名单', true);
  }

  const paste_length_rangeValue = Number(pick(data, 'maxLength'));
  if (Number.isFinite(paste_length_rangeValue) && (paste_length_rangeValue < 0 || paste_length_rangeValue > 1048576)) {
    add(REASON.PASTE_LENGTH_RANGE, '粘贴内容长度上限超出区间', false);
  }

  const paste_mime_emptyList = Array.isArray(pick(data, 'mimes')) ? pick(data, 'mimes') : [];
  if (paste_mime_emptyList.length === 0) {
    add(REASON.PASTE_MIME_EMPTY, '粘贴 MIME 白名单为空', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describePasteInSanitizerGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluatePasteInSanitizerGuard, describePasteInSanitizerGuard };
