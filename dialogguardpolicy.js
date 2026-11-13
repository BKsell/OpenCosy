"use strict";

const DIALOG_SHOW = 'show';
const DIALOG_SUPPRESS = 'suppress';

const DIALOG_ALERT = 'alert';
const DIALOG_CONFIRM = 'confirm';
const DIALOG_PROMPT = 'prompt';
const DIALOG_BEFOREUNLOAD = 'beforeunload';
const DIALOG_OTHER = 'other';

const SUPPRESS_BURST = 'dialog-burst-exceeded';
const SUPPRESS_LONG = 'dialog-long-exceeded';
const SUPPRESS_COOLDOWN = 'dialog-cooldown-active';
const SUPPRESS_DUPLICATE = 'dialog-duplicate-message';
const SUPPRESS_MALFORMED = 'dialog-malformed-message';

const DIALOG_BURST_WINDOW_MS = 10_000;
const DIALOG_BURST_LIMIT = 3;
const DIALOG_LONG_WINDOW_MS = 60_000;
const DIALOG_LONG_LIMIT = 8;
const DIALOG_COOLDOWN_MS = 20_000;
const DIALOG_DUP_MS = 750;
const DIALOG_MESSAGE_MAX_LEN = 2_000;

const JS_TYPES = new Set([DIALOG_ALERT, DIALOG_CONFIRM, DIALOG_PROMPT]);

// classifyType 把 Electron 上报的弹窗类型归一到本内核的常量。
function createDialogState(now) {
  return {
    origin: '',
    requestTimes: [],
    suppressedCount: 0,
    shownCount: 0,
    cooldownUntil: 0,
    // 最近一次展示的弹窗指纹：type + 规范化文案 + 时间戳。
    lastType: '',
    lastFingerprint: '',
    lastShownAt: 0,
    burstReportedAt: 0,
    longReportedAt: 0,
    dupReportedAt: 0,
    createdAt: now || 0,
  };
}

// decideDialog 裁决一次 JS 弹窗是否展示。
// input: { type?: string, message?: string, originUrl?: string }
// 返回 { decision, reason, origin, type, message, burstCount, longCount, cooldownUntil }。
// beforeunload / 未知类型返回 DIALOG_SHOW 且不计数（交由对应处理器）。
function decideDialog(state, input, now) {
  const inp = input || {};
  if (!state) {
    return {
      decision: DIALOG_SUPPRESS, reason: SUPPRESS_BURST, origin: '',
      type: DIALOG_OTHER, message: '', burstCount: 0, longCount: 0, cooldownUntil: 0,
    };
  }
  const type = classifyType(inp.type);
  const norm = normalizeMessage(inp.message);
  const origin = originFromUrl(inp.originUrl);
  if (origin) state.origin = origin;

  if (type === DIALOG_BEFOREUNLOAD || type === DIALOG_OTHER) {
    return {
      decision: DIALOG_SHOW, reason: '', origin, type, message: norm.message,
      burstCount: 0, longCount: 0, cooldownUntil: 0,
    };
  }

  const pushAndCount = () => {
    state.requestTimes.push(now);
    pruneOlderThan(state.requestTimes, now - DIALOG_LONG_WINDOW_MS);
    return {
      longCount: state.requestTimes.length,
      burstCount: countSince(state.requestTimes, now - DIALOG_BURST_WINDOW_MS),
    };
  };

  // 冷却期内一律抑制。
  if (state.cooldownUntil > now) {
    const c = pushAndCount();
    state.suppressedCount += 1;
    return {
      decision: DIALOG_SUPPRESS, reason: SUPPRESS_COOLDOWN, origin, type,
      message: norm.message, cooldownUntil: state.cooldownUntil, ...c,
    };
  }

  // 同文案递归弹窗：与上一次展示的 type+指纹相同且间隔极短，直接抑制（去抖留痕限频）。
  const fingerprint = `${type}\u0000${norm.message}`;
  if (state.lastFingerprint === fingerprint && state.lastType === type &&
      now - state.lastShownAt < DIALOG_DUP_MS) {
    const c = pushAndCount();
    state.suppressedCount += 1;
    state.lastFingerprint = fingerprint;
    state.lastType = type;
    return {
      decision: DIALOG_SUPPRESS, reason: SUPPRESS_DUPLICATE, origin, type,
      message: norm.message, cooldownUntil: 0, ...c,
    };
  }

  const c = pushAndCount();
  let reason = '';
  if (c.burstCount > DIALOG_BURST_LIMIT) {
    reason = SUPPRESS_BURST;
  } else if (c.longCount > DIALOG_LONG_LIMIT) {
    reason = SUPPRESS_LONG;
  }
  if (reason) {
    state.cooldownUntil = now + DIALOG_COOLDOWN_MS;
    state.suppressedCount += 1;
    if (reason === SUPPRESS_BURST) state.burstReportedAt = now;
    else state.longReportedAt = now;
    return {
      decision: DIALOG_SUPPRESS, reason, origin, type,
      message: norm.message, cooldownUntil: state.cooldownUntil, ...c,
    };
  }

  state.shownCount += 1;
  state.lastType = type;
  state.lastFingerprint = fingerprint;
  state.lastShownAt = now;
  return {
    decision: DIALOG_SHOW, reason: norm.malformed ? SUPPRESS_MALFORMED : '',
    origin, type, message: norm.message, cooldownUntil: 0, ...c,
  };
}

module.exports = { DIALOG_SHOW, DIALOG_SUPPRESS, DIALOG_ALERT, DIALOG_CONFIRM, DIALOG_PROMPT, DIALOG_BEFOREUNLOAD, DIALOG_OTHER, SUPPRESS_BURST, SUPPRESS_LONG, SUPPRESS_COOLDOWN, SUPPRESS_DUPLICATE, SUPPRESS_MALFORMED, DIALOG_BURST_WINDOW_MS, DIALOG_BURST_LIMIT, DIALOG_LONG_WINDOW_MS, DIALOG_LONG_LIMIT, DIALOG_COOLDOWN_MS, DIALOG_DUP_MS, DIALOG_MESSAGE_MAX_LEN, JS_TYPES, createDialogState, decideDialog };
