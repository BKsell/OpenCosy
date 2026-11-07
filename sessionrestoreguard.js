'use strict';

const REASON = {
  RESTORE_PLAINTEXT: 'restore-plaintext',
  RESTORE_TAB_NOT_HTTPS: 'restore-tab-not-https',
  RESTORE_TAB_LIMIT: 'restore-tab-limit',
  RESTORE_TAB_EMPTY: 'restore-tab-empty',
  RESTORE_AUTO_RISK: 'restore-auto-risk',
};

const LIMITS = {
  MAX_TABS: 50,
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

function evaluateSessionRestoreGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'encrypted') !== true) {
    add(REASON.RESTORE_PLAINTEXT, '会话恢复未加密存储', true);
  }

  const restore_tab_not_httpsList = Array.isArray(pick(data, 'tabs')) ? pick(data, 'tabs') : [];
  const restore_tab_not_httpsHit = restore_tab_not_httpsList.some((item) => new RegExp('^(?!https://).').test(String((item && typeof item === 'object' ? item.url : item) || '')));
  if (restore_tab_not_httpsHit) {
    add(REASON.RESTORE_TAB_NOT_HTTPS, '恢复的标签页地址不是 HTTPS', true);
  }

  const restore_tab_limitList = Array.isArray(pick(data, 'tabs')) ? pick(data, 'tabs') : [];
  if (restore_tab_limitList.length > 50) {
    add(REASON.RESTORE_TAB_LIMIT, '恢复标签页数量超出上限', false);
  }

  const restore_tab_emptyList = Array.isArray(pick(data, 'tabs')) ? pick(data, 'tabs') : [];
  if (restore_tab_emptyList.some((item) => !String(item || '').trim())) {
    add(REASON.RESTORE_TAB_EMPTY, '恢复标签页地址为空', true);
  }

  if (pick(data, 'restoreOnStartup') === true) {
    add(REASON.RESTORE_AUTO_RISK, '启动即恢复全部会话会让本地状态暴露', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeSessionRestoreGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateSessionRestoreGuard, describeSessionRestoreGuard };
