'use strict';

const REASON = {
  TAB_AUDIO_INDICATOR_OFF: 'tab-audio-indicator-off',
  TAB_AUDIO_MISSING_ID: 'tab-audio-missing-id',
  TAB_AUDIO_DUPLICATE_ID: 'tab-audio-duplicate-id',
  TAB_AUDIO_STATE_MISMATCH: 'tab-audio-state-mismatch',
  TAB_AUDIO_LIMIT: 'tab-audio-limit',
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

function evaluateTabAudioIndicatorGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  if (pick(data, 'showIndicator') !== true) {
    add(REASON.TAB_AUDIO_INDICATOR_OFF, '可发声标签页未开启声音指示', false);
  }

  const tab_audio_missing_idList = Array.isArray(pick(data, 'tabs')) ? pick(data, 'tabs') : [];
  if (tab_audio_missing_idList.some((item) => !item || !String(item.id || '').trim())) {
    add(REASON.TAB_AUDIO_MISSING_ID, '标签页缺少稳定标识', true);
  }

  const tab_audio_duplicate_idList = Array.isArray(pick(data, 'tabs')) ? pick(data, 'tabs') : [];
  const tab_audio_duplicate_idSeen = new Set();
  let tab_audio_duplicate_idDup = false;
  for (const item of tab_audio_duplicate_idList) {
    const marker = String((item && typeof item === 'object' ? item.id : item) || '').toLowerCase();
    if (!marker) continue;
    if (tab_audio_duplicate_idSeen.has(marker)) tab_audio_duplicate_idDup = true;
    tab_audio_duplicate_idSeen.add(marker);
  }
  if (tab_audio_duplicate_idDup) {
    add(REASON.TAB_AUDIO_DUPLICATE_ID, '标签页标识重复', true);
  }

  if (pick(data, 'stateMismatch') === true) {
    add(REASON.TAB_AUDIO_STATE_MISMATCH, '静音状态与可发声状态矛盾', false);
  }

  const tab_audio_limitList = Array.isArray(pick(data, 'tabs')) ? pick(data, 'tabs') : [];
  if (tab_audio_limitList.length > 64) {
    add(REASON.TAB_AUDIO_LIMIT, '同时跟踪的标签页过多', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeTabAudioIndicatorGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateTabAudioIndicatorGuard, describeTabAudioIndicatorGuard };
