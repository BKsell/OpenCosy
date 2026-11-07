'use strict';

const REASON = {
  EXTENSION_PERM_UNKNOWN: 'extension-perm-unknown',
  EXTENSION_PERM_DANGEROUS: 'extension-perm-dangerous',
  EXTENSION_HOST_WILDCARD: 'extension-host-wildcard',
  EXTENSION_PERM_LIMIT: 'extension-perm-limit',
};

const LIMITS = {
  MAX_PERMISSIONS: 12,
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

function evaluateExtensionPermissionGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const extension_perm_unknownList = Array.isArray(pick(data, 'permissions')) ? pick(data, 'permissions') : [];
  const extension_perm_unknownHit = extension_perm_unknownList.some((item) => !['storage', 'tabs', 'cookies', 'webrequest', 'nativemessaging'].includes(String((item && typeof item === 'object' ? item : item) || '').toLowerCase()));
  if (extension_perm_unknownHit) {
    add(REASON.EXTENSION_PERM_UNKNOWN, '扩展权限不在已知集合', false);
  }

  const extension_perm_dangerousList = Array.isArray(pick(data, 'permissions')) ? pick(data, 'permissions') : [];
  const extension_perm_dangerousHit = extension_perm_dangerousList.some((item) => ['nativemessaging', 'debugger', 'proxy'].includes(String((item && typeof item === 'object' ? item : item) || '').toLowerCase()));
  if (extension_perm_dangerousHit) {
    add(REASON.EXTENSION_PERM_DANGEROUS, '扩展申请高危权限', true);
  }

  const extension_host_wildcardList = Array.isArray(pick(data, 'hosts')) ? pick(data, 'hosts') : [];
  const extension_host_wildcardHit = extension_host_wildcardList.some((item) => new RegExp('<all_urls>|\\*').test(String((item && typeof item === 'object' ? item : item) || '')));
  if (extension_host_wildcardHit) {
    add(REASON.EXTENSION_HOST_WILDCARD, '扩展主机权限使用通配', true);
  }

  const extension_perm_limitList = Array.isArray(pick(data, 'permissions')) ? pick(data, 'permissions') : [];
  if (extension_perm_limitList.length > 12) {
    add(REASON.EXTENSION_PERM_LIMIT, '扩展权限数量超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeExtensionPermissionGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateExtensionPermissionGuard, describeExtensionPermissionGuard };
