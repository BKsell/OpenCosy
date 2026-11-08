'use strict';

// dialogguard.js —— 网页 JS 模态对话框（alert/confirm/prompt）的滥用/DoS 收口内核。
//
// 威胁模型：
//   alert()/confirm()/prompt() 会拉起应用级阻塞模态框，模态期间整个窗口停止响应输入。
//   恶意页可以：
//     1) 在定时器或前一个弹窗关闭回调里递归弹窗，形成“关不完”的轰炸（拒绝服务）；
//     2) 用完全相同的文案无限 confirm() 实施诈骗/疲劳点击（点错“是”即授权）；
//     3) 塞超长 / 含控制字符的消息撑爆布局、伪造系统语气。
//   Electron 的 webContents 'dialog' 事件可 preventDefault() 取消本次内置对话框，
//   因此与 printguard 同构，用“滑动窗口配额 + 冷却 + 同文案去抖”收敛：
//     - 短窗口（10s）突发上限 DIALOG_BURST_LIMIT；
//     - 长窗口（60s）总量上限 DIALOG_LONG_LIMIT；
//     - 同一 type+同一规范化文案在 DIALOG_DUP_MS 内重复，直接抑制（递归同文案弹窗）；
//     - 任一窗口越限进入冷却，冷却期内全部抑制。
//   beforeunload 类型不在此内核处理（由 unloadguard 统一裁决），这里显式放行/跳过，
//   避免两处对同一弹窗重复计数。
//   本模块只做纯判定，main.js 监听 'dialog'、按结果 preventDefault 并留痕。

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
function classifyType(rawType) {
  const t = String(rawType || '').toLowerCase();
  if (JS_TYPES.has(t)) return t;
  if (t === DIALOG_BEFOREUNLOAD) return DIALOG_BEFOREUNLOAD;
  return DIALOG_OTHER;
}

// isBeforeUnload 供接线处分流：beforeunload 由 unloadguard 裁决，本内核不计数。
function isBeforeUnload(rawType) {
  return classifyType(rawType) === DIALOG_BEFOREUNLOAD;
}

// normalizeMessage 规整弹窗文案：非字符串按空处理，去除 C0/C1 控制字符（保留常规空白），
// 折叠连续空白并截断长度；changed/truncated 用于判定畸形输入。
function normalizeMessage(rawMessage) {
  let s = typeof rawMessage === 'string' ? rawMessage : '';
  const original = s;
  // 去掉除常见水平空白/tab/换行外的控制字符；再把所有连续空白压成一个空格。
  s = s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, '');
  s = s.replace(/\s+/g, ' ').trim();
  const changed = s !== original.trim();
  let truncated = false;
  if (s.length > DIALOG_MESSAGE_MAX_LEN) {
    s = s.slice(0, DIALOG_MESSAGE_MAX_LEN);
    truncated = true;
  }
  return { message: s, changed, truncated, malformed: changed || truncated };
}

function originFromUrl(rawUrl) {
  try {
    return new URL(rawUrl || '').origin;
  } catch {
    return '';
  }
}

function pruneOlderThan(list, cutoff) {
  let i = 0;
  while (i < list.length && list[i] < cutoff) i++;
  if (i > 0) list.splice(0, i);
}

function countSince(sortedTimes, cutoff) {
  let n = 0;
  for (let i = sortedTimes.length - 1; i >= 0; i--) {
    if (sortedTimes[i] >= cutoff) n++;
    else break;
  }
  return n;
}

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

function inCooldown(state, now) {
  return !!state && state.cooldownUntil > now;
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

function resetCooldown(state) {
  if (state) state.cooldownUntil = 0;
}

function describeDialogReason(reason) {
  switch (reason) {
    case SUPPRESS_BURST:
      return '网页在短时间内连续弹出模态对话框（疑似弹窗轰炸），本次已拦截';
    case SUPPRESS_LONG:
      return '网页持续高频弹出对话框，本次已拦截并进入冷却';
    case SUPPRESS_COOLDOWN:
      return '对话框冷却期内的重复弹窗已拦截';
    case SUPPRESS_DUPLICATE:
      return '网页连续弹出相同文案的对话框，已合并拦截';
    case SUPPRESS_MALFORMED:
      return '对话框文案含异常控制字符或超长，已做净化展示';
    default:
      return '对话框请求';
  }
}

module.exports = {
  DIALOG_SHOW,
  DIALOG_SUPPRESS,
  DIALOG_ALERT,
  DIALOG_CONFIRM,
  DIALOG_PROMPT,
  DIALOG_BEFOREUNLOAD,
  DIALOG_OTHER,
  SUPPRESS_BURST,
  SUPPRESS_LONG,
  SUPPRESS_COOLDOWN,
  SUPPRESS_DUPLICATE,
  SUPPRESS_MALFORMED,
  DIALOG_BURST_WINDOW_MS,
  DIALOG_BURST_LIMIT,
  DIALOG_LONG_WINDOW_MS,
  DIALOG_LONG_LIMIT,
  DIALOG_COOLDOWN_MS,
  DIALOG_DUP_MS,
  DIALOG_MESSAGE_MAX_LEN,
  classifyType,
  isBeforeUnload,
  normalizeMessage,
  originFromUrl,
  createDialogState,
  inCooldown,
  decideDialog,
  resetCooldown,
  describeDialogReason,
};
