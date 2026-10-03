'use strict';

// fullscreenguard.js —— HTML 全屏与键盘锁（navigator.keyboard.lock）的滥用收口内核。
//
// 威胁模型：
//   1. 键盘锁（Keyboard Lock API）：网页调用 navigator.keyboard.lock(["Escape",...])
//      后，页面可捕获本应由浏览器/系统处理的按键（典型目标是 Esc——退出全屏的标准
//      逃生键，以及 Ctrl+W/T/N 等窗口快捷键）。它的正当场景几乎只有“已处于全屏”
//      的网页游戏 / 远程桌面。普通标签页在窗口态请求键盘锁没有合理用途，却是钓鱼页
//      “先锁键、再伪造系统/银行界面”的标准起手式。因此策略是：仅当该内容正处于
//      HTML 全屏时才放行键盘锁，窗口态一律拒绝并留痕。
//   2. 全屏抖动（fullscreen flicker）：恶意页可以在极短时间内反复
//      requestFullscreen() / document.exitFullscreen()，配合光标伪装或伪造的权限
//      提示条制造点击劫持（用户以为点向浏览器原生 UI，实际落点在页面元素上）。
//      这里对“滑动时间窗内的进入/退出次数”做限速，越过阈值即判为滥用并提级留痕。
//
// 本模块只做纯判定与入参归一（可被 node:test 直接覆盖），不持有 Electron 对象；
// main.js 负责创建每 contents 状态、监听事件、preventDefault 与 recordSecurityEvent。

const KEYBOARD_ALLOW = 'allow';
const KEYBOARD_DENY = 'deny';

const DENY_NOT_FULLSCREEN = 'keyboard-lock-requires-fullscreen';
const DENY_RATE_LIMITED = 'keyboard-lock-rate-limited';
const DENY_BAD_STATE = 'keyboard-lock-bad-state';

const ABUSE_FLICKER = 'fullscreen-flicker';

// 滑动时间窗与阈值。
// 键盘锁：5 秒内最多 3 次请求（正常页面进入全屏时请求一次即可，反复申请属异常）。
// 全屏切换：10 秒内进入/退出合计超过 8 次视为抖动滥用（真人几乎不可能手动做到）。
const KEYBOARD_LOCK_WINDOW_MS = 5000;
const KEYBOARD_LOCK_LIMIT = 3;
const FULLSCREEN_SWITCH_WINDOW_MS = 10000;
const FULLSCREEN_SWITCH_LIMIT = 8;

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

function createFullscreenState(now) {
  return {
    fullscreen: false,
    origin: '',
    enterCount: 0,
    leaveCount: 0,
    lastEnterAt: 0,
    lastLeaveAt: 0,
    // 进入与退出时刻合并记录，用于抖动计数。
    switchTimes: [],
    keyboardLocked: false,
    // 已记录的键盘锁请求时刻（无论放行/拒绝都计数，防止“被拒后无限重试”探测）。
    lockRequestTimes: [],
    deniedLockCount: 0,
    flickerReportedAt: 0,
    createdAt: now || 0,
  };
}

// noteEnter 记录一次进入全屏。返回 { abusive }：当本次进入使滑动窗口内切换数越过
// 阈值时 abusive=true（main.js 只在“越线当下”留痕一次，避免每个事件都刷审计）。
function noteEnter(state, now, originUrl) {
  if (!state) return { abusive: false };
  state.fullscreen = true;
  state.enterCount += 1;
  state.lastEnterAt = now;
  if (originUrl) state.origin = originFromUrl(originUrl);
  state.switchTimes.push(now);
  pruneOlderThan(state.switchTimes, now - FULLSCREEN_SWITCH_WINDOW_MS);
  const abusive = state.switchTimes.length > FULLSCREEN_SWITCH_LIMIT &&
    now - state.flickerReportedAt > FULLSCREEN_SWITCH_WINDOW_MS;
  if (abusive) state.flickerReportedAt = now;
  return { abusive };
}

// noteLeave 记录一次退出全屏，并清除键盘锁状态（离开全屏后锁不应继续生效）。
function noteLeave(state, now) {
  if (!state) return { abusive: false };
  state.fullscreen = false;
  state.keyboardLocked = false;
  state.leaveCount += 1;
  state.lastLeaveAt = now;
  state.switchTimes.push(now);
  pruneOlderThan(state.switchTimes, now - FULLSCREEN_SWITCH_WINDOW_MS);
  const abusive = state.switchTimes.length > FULLSCREEN_SWITCH_LIMIT &&
    now - state.flickerReportedAt > FULLSCREEN_SWITCH_WINDOW_MS;
  if (abusive) state.flickerReportedAt = now;
  return { abusive };
}

// currentSwitchRate 返回当前窗口内的切换次数（供展示/测试，不改变状态）。
function currentSwitchRate(state, now) {
  if (!state) return 0;
  pruneOlderThan(state.switchTimes, now - FULLSCREEN_SWITCH_WINDOW_MS);
  return state.switchTimes.length;
}

// decideKeyboardLock 判定一次 navigator.keyboard.lock() 请求。
// input: { fullscreen?: boolean（缺省取 state.fullscreen）, originUrl?: string, keys?: string[] }
// 返回 { decision, reason, origin, requestCount }；同时把本次请求计入限速窗口。
function decideKeyboardLock(state, input, now) {
  const inp = input || {};
  if (!state) {
    return { decision: KEYBOARD_DENY, reason: DENY_BAD_STATE, origin: '', requestCount: 0 };
  }
  const origin = originFromUrl(inp.originUrl);
  state.lockRequestTimes.push(now);
  pruneOlderThan(state.lockRequestTimes, now - KEYBOARD_LOCK_WINDOW_MS);
  const requestCount = state.lockRequestTimes.length;

  const isFullscreen = typeof inp.fullscreen === 'boolean' ? inp.fullscreen : state.fullscreen;
  if (!isFullscreen) {
    state.deniedLockCount += 1;
    return { decision: KEYBOARD_DENY, reason: DENY_NOT_FULLSCREEN, origin, requestCount };
  }
  // 允许第 KEYBOARD_LOCK_LIMIT 次、拒绝第 LIMIT+1 次：窗口内长度超过阈值即拒。
  if (requestCount > KEYBOARD_LOCK_LIMIT) {
    state.deniedLockCount += 1;
    return { decision: KEYBOARD_DENY, reason: DENY_RATE_LIMITED, origin, requestCount };
  }
  state.keyboardLocked = true;
  return { decision: KEYBOARD_ALLOW, reason: '', origin, requestCount };
}

// noteKeyboardUnlock 在页面主动 unlock（或导航）时复位锁标记。
function noteKeyboardUnlock(state) {
  if (!state) return;
  state.keyboardLocked = false;
}

// describeKeyboardDecision / describeAbuse 给出安全事件中文文案。
function describeKeyboardReason(reason) {
  switch (reason) {
    case DENY_NOT_FULLSCREEN:
      return '网页在非全屏状态请求键盘锁（可能意图劫持 Esc 等按键），已阻止';
    case DENY_RATE_LIMITED:
      return '网页在短时间内反复请求键盘锁，已按滥用限速阻止';
    case DENY_BAD_STATE:
      return '键盘锁请求缺少有效内容状态，已阻止';
    default:
      return '键盘锁请求';
  }
}

function describeAbuse(kind) {
  switch (kind) {
    case ABUSE_FLICKER:
      return '网页在短时间内高频进出全屏（疑似全屏点击劫持），已记录';
    default:
      return '全屏状态异常';
  }
}

module.exports = {
  KEYBOARD_ALLOW,
  KEYBOARD_DENY,
  DENY_NOT_FULLSCREEN,
  DENY_RATE_LIMITED,
  DENY_BAD_STATE,
  ABUSE_FLICKER,
  KEYBOARD_LOCK_WINDOW_MS,
  KEYBOARD_LOCK_LIMIT,
  FULLSCREEN_SWITCH_WINDOW_MS,
  FULLSCREEN_SWITCH_LIMIT,
  originFromUrl,
  createFullscreenState,
  noteEnter,
  noteLeave,
  currentSwitchRate,
  decideKeyboardLock,
  noteKeyboardUnlock,
  describeKeyboardReason,
  describeAbuse,
};
