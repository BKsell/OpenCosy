'use strict';

const REASON = {
  LOCALFILE_ALLOW_ALL: 'localfile-allow-all',
  LOCALFILE_SCHEME: 'localfile-scheme',
  LOCALFILE_ROOT_TRAVERSAL: 'localfile-root-traversal',
  LOCALFILE_ROOT_LIMIT: 'localfile-root-limit',
  LOCALFILE_URL_TRAVERSAL: 'localfile-url-traversal',
};

const LIMITS = {
  MAX_ROOTS: 10,
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

function evaluateLocalFileAccessGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'allowAll') === true) {
    add(REASON.LOCALFILE_ALLOW_ALL, '允许访问任意本地文件', true);
  }

  if (pick(data, 'allowFileScheme') === true) {
    add(REASON.LOCALFILE_SCHEME, '允许 file: 协议直接打开本地文件', true);
  }

  const localfile_root_traversalList = Array.isArray(pick(data, 'roots')) ? pick(data, 'roots') : [];
  const localfile_root_traversalHit = localfile_root_traversalList.some((item) => new RegExp('\\.\\.').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (localfile_root_traversalHit) {
    add(REASON.LOCALFILE_ROOT_TRAVERSAL, '本地访问根目录包含穿越', true);
  }

  const localfile_root_limitList = Array.isArray(pick(data, 'roots')) ? pick(data, 'roots') : [];
  if (localfile_root_limitList.length > 10) {
    add(REASON.LOCALFILE_ROOT_LIMIT, '本地访问根目录超出上限', false);
  }

  if (text(pick(data, 'url')).includes('..')) {
    add(REASON.LOCALFILE_URL_TRAVERSAL, '本地文件地址包含穿越', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeLocalFileAccessGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateLocalFileAccessGuard, describeLocalFileAccessGuard };
