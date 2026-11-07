'use strict';

const REASON = {
  CLIPBOARD_CONFIRM_OFF: 'clipboard-confirm-off',
  CLIPBOARD_MIME_UNKNOWN: 'clipboard-mime-unknown',
  CLIPBOARD_SIZE_RANGE: 'clipboard-size-range',
  CLIPBOARD_MIME_EMPTY: 'clipboard-mime-empty',
};

const LIMITS = {
  MAX_BYTES: 1048576,
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

function evaluateClipboardPasteConfirmGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'confirmBeforePaste') !== true) {
    add(REASON.CLIPBOARD_CONFIRM_OFF, '粘贴前未要求确认', false);
  }

  const clipboard_mime_unknownList = Array.isArray(pick(data, 'mimes')) ? pick(data, 'mimes') : [];
  const clipboard_mime_unknownHit = clipboard_mime_unknownList.some((item) => !['text/plain', 'image/png'].includes(String((item && typeof item === 'object' ? item : item) || '').toLowerCase()));
  if (clipboard_mime_unknownHit) {
    add(REASON.CLIPBOARD_MIME_UNKNOWN, '粘贴 MIME 不在白名单', true);
  }

  const clipboard_size_rangeValue = Number(pick(data, 'maxBytes'));
  if (Number.isFinite(clipboard_size_rangeValue) && (clipboard_size_rangeValue < 0 || clipboard_size_rangeValue > 1048576)) {
    add(REASON.CLIPBOARD_SIZE_RANGE, '粘贴体积上限超出配额', false);
  }

  const clipboard_mime_emptyList = Array.isArray(pick(data, 'mimes')) ? pick(data, 'mimes') : [];
  if (clipboard_mime_emptyList.length === 0) {
    add(REASON.CLIPBOARD_MIME_EMPTY, '粘贴 MIME 白名单为空', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeClipboardPasteConfirmGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateClipboardPasteConfirmGuard, describeClipboardPasteConfirmGuard };
