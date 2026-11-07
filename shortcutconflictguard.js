'use strict';

const REASON = {
  SHORTCUT_DUPLICATE_KEY: 'shortcut-duplicate-key',
  SHORTCUT_RESERVED_KEY: 'shortcut-reserved-key',
  SHORTCUT_ACTION_EMPTY: 'shortcut-action-empty',
  SHORTCUT_LIMIT: 'shortcut-limit',
  SHORTCUT_KEY_EMPTY: 'shortcut-key-empty',
};

const LIMITS = {
  MAX_SHORTCUTS: 30,
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

function evaluateShortcutConflictGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const shortcut_duplicate_keyList = Array.isArray(pick(data, 'shortcuts')) ? pick(data, 'shortcuts') : [];
  const shortcut_duplicate_keySeen = new Set();
  let shortcut_duplicate_keyDup = false;
  for (const item of shortcut_duplicate_keyList) {
    const marker = String((item && typeof item === 'object' ? item.key : item) || '').toLowerCase();
    if (!marker) continue;
    if (shortcut_duplicate_keySeen.has(marker)) shortcut_duplicate_keyDup = true;
    shortcut_duplicate_keySeen.add(marker);
  }
  if (shortcut_duplicate_keyDup) {
    add(REASON.SHORTCUT_DUPLICATE_KEY, '快捷键重复绑定', true);
  }

  const shortcut_reserved_keyList = Array.isArray(pick(data, 'shortcuts')) ? pick(data, 'shortcuts') : [];
  const shortcut_reserved_keyReserved = (Array.isArray(pick(data, 'reserved')) ? pick(data, 'reserved') : [])
    .map((entry) => String(entry || '').toLowerCase());
  if (shortcut_reserved_keyList.some((item) => shortcut_reserved_keyReserved.includes(String(item.key || '').toLowerCase()))) {
    add(REASON.SHORTCUT_RESERVED_KEY, '快捷键占用了保留组合', true);
  }

  const shortcut_action_emptyList = Array.isArray(pick(data, 'shortcuts')) ? pick(data, 'shortcuts') : [];
  if (shortcut_action_emptyList.some((item) => !item || !String(item.action || '').trim())) {
    add(REASON.SHORTCUT_ACTION_EMPTY, '快捷键缺少动作名', true);
  }

  const shortcut_limitList = Array.isArray(pick(data, 'shortcuts')) ? pick(data, 'shortcuts') : [];
  if (shortcut_limitList.length > 30) {
    add(REASON.SHORTCUT_LIMIT, '快捷键数量超出上限', false);
  }

  const shortcut_key_emptyList = Array.isArray(pick(data, 'shortcuts')) ? pick(data, 'shortcuts') : [];
  if (shortcut_key_emptyList.some((item) => !item || !String(item.key || '').trim())) {
    add(REASON.SHORTCUT_KEY_EMPTY, '快捷键组合为空', true);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeShortcutConflictGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateShortcutConflictGuard, describeShortcutConflictGuard };
