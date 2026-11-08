'use strict';

const REASON = {
  UPDATE_URL_NOT_HTTPS: 'update-url-not-https',
  UPDATE_AUTO_RISK: 'update-auto-risk',
  UPDATE_URL_CREDENTIALS: 'update-url-credentials',
  UPDATE_HOST_LIMIT: 'update-host-limit',
};

const LIMITS = {
  MAX_HOSTS: 3,
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

function evaluateWebExtensionUpdateGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (new RegExp('^(?!https://).').test(text(pick(data, 'updateUrl')))) {
    add(REASON.UPDATE_URL_NOT_HTTPS, '扩展更新地址不是 HTTPS', true);
  }

  if (pick(data, 'autoUpdate') === true) {
    add(REASON.UPDATE_AUTO_RISK, '自动更新会引入未经审阅的代码', false);
  }

  if (new RegExp('://[^/@]+@').test(text(pick(data, 'updateUrl')))) {
    add(REASON.UPDATE_URL_CREDENTIALS, '扩展更新地址内嵌凭据', true);
  }

  const update_host_limitList = Array.isArray(pick(data, 'hosts')) ? pick(data, 'hosts') : [];
  if (update_host_limitList.length > 3) {
    add(REASON.UPDATE_HOST_LIMIT, '更新白名单数量超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeWebExtensionUpdateGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateWebExtensionUpdateGuard, describeWebExtensionUpdateGuard };
