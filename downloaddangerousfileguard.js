'use strict';

const REASON = {
  DOWNLOAD_BLOCKED_EXT: 'download-blocked-ext',
  DOWNLOAD_DOUBLE_EXT: 'download-double-ext',
  DOWNLOAD_NAME_TRAVERSAL: 'download-name-traversal',
  DOWNLOAD_NAME_TOO_LONG: 'download-name-too-long',
  DOWNLOAD_URL_NOT_HTTPS: 'download-url-not-https',
};

const LIMITS = {
  MAX_NAME: 255,
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

function evaluateDownloadDangerousFileGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (['.exe', '.scr', '.bat', '.cmd', '.ps1'].some((suffix) => text(pick(data, 'filename')).toLowerCase().endsWith(suffix))) {
    add(REASON.DOWNLOAD_BLOCKED_EXT, '下载文件扩展名在阻断列表', true);
  }

  if (new RegExp('\\.(pdf|docx?|xlsx?)\\.(exe|scr|js)$').test(text(pick(data, 'filename')))) {
    add(REASON.DOWNLOAD_DOUBLE_EXT, '下载文件使用双扩展名伪装', true);
  }

  if (text(pick(data, 'filename')).includes('..')) {
    add(REASON.DOWNLOAD_NAME_TRAVERSAL, '下载文件名包含路径穿越', true);
  }

  if (text(pick(data, 'filename')).length > 255) {
    add(REASON.DOWNLOAD_NAME_TOO_LONG, '下载文件名长度超出上限', false);
  }

  if (new RegExp('^(?!https://).').test(text(pick(data, 'url')))) {
    add(REASON.DOWNLOAD_URL_NOT_HTTPS, '下载地址不是 HTTPS', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeDownloadDangerousFileGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateDownloadDangerousFileGuard, describeDownloadDangerousFileGuard };
