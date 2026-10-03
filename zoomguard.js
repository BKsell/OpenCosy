'use strict';

// zoomguard.js —— 页面缩放级别（zoom-changed / setZoomLevel）的越界与事件洪泛收口。
//
// 威胁模型 / 问题面：
//   1. 越界缩放：Chromium 的缩放级别（setZoomLevel，系数 = 1.2^level）取值很宽。
//      若某条链路把外部传入值直接交给 setZoomLevel，极端级别会让页面布局崩坏，甚至触发
//      合成层的高内存分配。这里以 Chromium 级别口径统一钳制到 [-8, 9]（约 0.23 ~ 5.16
//      倍），与主进程已有的系数钳制（0.25 ~ 5）对齐，并量化到 0.5 级抑制亚像素抖动。
//   2. zoom-changed 事件洪泛：用户按住 Ctrl 狂滚滚轮、或某些页面/输入设备抖动时，
//      webContents 的 zoom-changed / 级别变化会在极短时间内高频触发，主进程每收到一次
//      就向渲染层广播一次缩放百分比并写状态，属于放大效应明显的 IPC 洪泛（几百 Hz 时
//      会拖慢整个界面）。本内核对“向渲染层广播”做合并：同一级别只广播一次；级别确有
//      变化时也施加最小广播间隔，窗口内超出突发上限的重复变化只更新内部值、不广播。
//
// 纯判定模块，不触碰 Electron 对象；main.js 持有每 contents 状态并决定是否广播。

// 以系数钳制（主进程 0.25 ~ 5）反推：log_1.2(0.25) ≈ -7.6 -> -8（系数约 0.23），
// log_1.2(5) ≈ 8.8 -> 9（系数约 5.16）。取级别区间 [-8, 9] 与系数钳制对齐。
const ZOOM_MIN_LEVEL = -8;
const ZOOM_MAX_LEVEL = 9;
const ZOOM_DEFAULT_LEVEL = 0; // 100%

// 相邻两次“有效广播”之间的最小间隔（毫秒），用于合并滚轮抖动。
const ZOOM_BROADCAST_MIN_INTERVAL_MS = 60;
// 1 秒滑动窗口内最多接受的级别变化事件数，超出部分只更新值不再广播（洪泛保护）。
const ZOOM_CHANGE_WINDOW_MS = 1000;
const ZOOM_CHANGE_LIMIT = 40;

const ACTION_BROADCAST = 'broadcast';
const ACTION_HOLD = 'hold';

const HOLD_SAME_LEVEL = 'zoom-same-level';
const HOLD_TOO_FAST = 'zoom-broadcast-too-fast';
const HOLD_FLOODED = 'zoom-change-flooded';
const HOLD_BAD_STATE = 'zoom-bad-state';

function clampZoomLevel(level) {
  const n = typeof level === 'number' && Number.isFinite(level) ? level : ZOOM_DEFAULT_LEVEL;
  if (n < ZOOM_MIN_LEVEL) return ZOOM_MIN_LEVEL;
  if (n > ZOOM_MAX_LEVEL) return ZOOM_MAX_LEVEL;
  // 四舍五入到 0.5 级，避免滚轮给出 0.0000001 级别的抖动不断触发“变化”。
  return Math.round(n * 2) / 2;
}

function zoomLevelToPercent(level) {
  // Chromium 缩放系数 = 1.2 ^ level。
  return Math.round(Math.pow(1.2, clampZoomLevel(level)) * 100);
}

function pruneOlderThan(list, cutoff) {
  let i = 0;
  while (i < list.length && list[i] < cutoff) i++;
  if (i > 0) list.splice(0, i);
}

function createZoomState(now) {
  return {
    level: ZOOM_DEFAULT_LEVEL,
    lastBroadcastLevel: ZOOM_DEFAULT_LEVEL,
    lastBroadcastAt: 0,
    changeTimes: [],
    floodReportedAt: 0,
    updatedAt: now || 0,
  };
}

// applyZoomChange 处理一次缩放级别变化（可能来自 zoom-changed 或程序化设置）。
// input: { level:number, now:number（也可用第二参） }
// 返回 { action, level, percent, reason, flooded }：
//   ACTION_BROADCAST 表示级别有效且应向渲染层广播；ACTION_HOLD 表示只更新/忽略、不广播。
function applyZoomChange(state, input, nowArg) {
  const inp = input || {};
  const now = typeof nowArg === 'number' ? nowArg : (typeof inp.now === 'number' ? inp.now : 0);
  if (!state) {
    return {
      action: ACTION_HOLD, level: ZOOM_DEFAULT_LEVEL,
      percent: zoomLevelToPercent(ZOOM_DEFAULT_LEVEL), reason: HOLD_BAD_STATE, flooded: false,
    };
  }

  const level = clampZoomLevel(inp.level);
  state.level = level;
  state.updatedAt = now;

  // 与上次已广播级别相同（含 0.5 级取整后相同）：无需重复广播。
  if (level === state.lastBroadcastLevel) {
    return { action: ACTION_HOLD, level, percent: zoomLevelToPercent(level), reason: HOLD_SAME_LEVEL, flooded: false };
  }

  // 统计原始变化频率用于洪泛检测（即使最终 hold 也计数）。
  state.changeTimes.push(now);
  pruneOlderThan(state.changeTimes, now - ZOOM_CHANGE_WINDOW_MS);
  const flooded = state.changeTimes.length > ZOOM_CHANGE_LIMIT;
  if (flooded && now - state.floodReportedAt > ZOOM_CHANGE_WINDOW_MS) {
    state.floodReportedAt = now;
  }

  if (flooded) {
    return { action: ACTION_HOLD, level, percent: zoomLevelToPercent(level), reason: HOLD_FLOODED, flooded: true };
  }
  if (state.lastBroadcastAt !== 0 && now - state.lastBroadcastAt < ZOOM_BROADCAST_MIN_INTERVAL_MS) {
    return { action: ACTION_HOLD, level, percent: zoomLevelToPercent(level), reason: HOLD_TOO_FAST, flooded: false };
  }

  state.lastBroadcastLevel = level;
  state.lastBroadcastAt = now;
  return { action: ACTION_BROADCAST, level, percent: zoomLevelToPercent(level), reason: '', flooded: false };
}

// flushPendingZoom 在洪泛/节流平息后调用：若内部级别与已广播级别不同，则补发一次。
// 返回 { action, level, percent }（无新变化时 ACTION_HOLD）。
function flushPendingZoom(state, now) {
  if (!state) {
    return { action: ACTION_HOLD, level: ZOOM_DEFAULT_LEVEL, percent: zoomLevelToPercent(ZOOM_DEFAULT_LEVEL) };
  }
  pruneOlderThan(state.changeTimes, (now || 0) - ZOOM_CHANGE_WINDOW_MS);
  if (state.level === state.lastBroadcastLevel) {
    return { action: ACTION_HOLD, level: state.level, percent: zoomLevelToPercent(state.level) };
  }
  state.lastBroadcastLevel = state.level;
  state.lastBroadcastAt = now || 0;
  return { action: ACTION_BROADCAST, level: state.level, percent: zoomLevelToPercent(state.level) };
}

function describeHoldReason(reason) {
  switch (reason) {
    case HOLD_SAME_LEVEL: return '缩放级别未变化';
    case HOLD_TOO_FAST: return '缩放广播过于密集，已合并';
    case HOLD_FLOODED: return '缩放事件疑似洪泛，已暂停广播';
    case HOLD_BAD_STATE: return '缺少有效缩放状态';
    default: return '缩放更新';
  }
}

module.exports = {
  ZOOM_MIN_LEVEL,
  ZOOM_MAX_LEVEL,
  ZOOM_DEFAULT_LEVEL,
  ZOOM_BROADCAST_MIN_INTERVAL_MS,
  ZOOM_CHANGE_WINDOW_MS,
  ZOOM_CHANGE_LIMIT,
  ACTION_BROADCAST,
  ACTION_HOLD,
  HOLD_SAME_LEVEL,
  HOLD_TOO_FAST,
  HOLD_FLOODED,
  HOLD_BAD_STATE,
  clampZoomLevel,
  zoomLevelToPercent,
  createZoomState,
  applyZoomChange,
  flushPendingZoom,
  describeHoldReason,
};
