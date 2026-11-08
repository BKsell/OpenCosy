'use strict';

const REASON = {
  MUTE_BADGE_OFF: 'mute-badge-off',
  MUTE_REMEMBER_RISK: 'mute-remember-risk',
  MUTE_TAB_MISSING_ID: 'mute-tab-missing-id',
  MUTE_TAB_LIMIT: 'mute-tab-limit',
};

const LIMITS = {
  MAX_TABS: 64,
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

function evaluateMuteIndicatorGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'badgeOff') === true) {
    add(REASON.MUTE_BADGE_OFF, '静音状态没有可视徽标', false);
  }

  if (pick(data, 'rememberMute') === true) {
    add(REASON.MUTE_REMEMBER_RISK, '跨站记忆静音状态存在隐私风险', false);
  }

  const mute_tab_missing_idList = Array.isArray(pick(data, 'tabs')) ? pick(data, 'tabs') : [];
  if (mute_tab_missing_idList.some((item) => !item || !String(item.id || '').trim())) {
    add(REASON.MUTE_TAB_MISSING_ID, '静音标签页缺少标识', true);
  }

  const mute_tab_limitList = Array.isArray(pick(data, 'tabs')) ? pick(data, 'tabs') : [];
  if (mute_tab_limitList.length > 64) {
    add(REASON.MUTE_TAB_LIMIT, '静音标签页数量超出上限', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeMuteIndicatorGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateMuteIndicatorGuard, describeMuteIndicatorGuard };
