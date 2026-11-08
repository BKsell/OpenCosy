'use strict';

// cursorguard.js —— 光标变更事件（webContents 'cursor-changed'）收口内核。
//
// 威胁模型：
//   页面用 CSS cursor: url(...) 可请求自定义光标，Chromium 在光标变化时抛
//   'cursor-changed'，参数含光标类型 type、位图 image、缩放 scale。风险：
//     1) 超大位图 DoS：恶意页面给一个极大尺寸的光标 PNG（几万×几万），Chromium 解码
//        后通过 IPC 把原生位图交给主进程/窗口层，造成内存尖峰与 IPC 大负载；
//     2) 光标类型抖动：脚本在元素树里高频切换 cursor，制造成千上万次 cursor-changed，
//        空耗主进程与渲染层；
//     3) 非预期类型字符串：自定义/未知类型必须落到默认光标，而不是带着脏值往下传。
//   策略：type 走白名单；custom 类型强制校验位图边长/字节与 scale 上下限；所有事件
//   （含被合并的）计入滑动窗口硬洪泛，越限冷却并整体回落 default。纯函数，无 Electron
//   依赖：位图尺寸由调用方从 nativeImage 读出后以 { width, height, bytes } 传入。

const CURSOR_APPLY = 'apply';   // 合法变更，允许应用光标
const CURSOR_HOLD = 'hold';     // 同类型重复或过快，合并
const CURSOR_DROP = 'drop';     // 非法/洪泛，回落默认光标

const HOLD_SAME = 'cursor-same-type';
const HOLD_TOO_SOON = 'cursor-too-soon';
const DROP_BAD_TYPE = 'cursor-bad-type';
const DROP_BAD_IMAGE = 'cursor-bad-image';
const DROP_BAD_SCALE = 'cursor-bad-scale';
const DROP_FLOOD = 'cursor-flood-exceeded';
const DROP_COOLDOWN = 'cursor-cooldown-active';

const CURSOR_MIN_INTERVAL_MS = 16; // 约 60fps，正常光标移动不会超这个变化频率
const CURSOR_BURST_WINDOW_MS = 1_000;
const CURSOR_BURST_LIMIT = 120;
const CURSOR_LONG_WINDOW_MS = 10_000;
const CURSOR_LONG_LIMIT = 1_000;
const CURSOR_COOLDOWN_MS = 2_000;

// 自定义光标资源上限。上限给得很宽（宁可偏大也不误伤正常高分辨率光标），但挡住
// “几万像素/几十 MB”级别的位图 DoS。
const CURSOR_MAX_EDGE_PX = 512;
const CURSOR_MAX_IMAGE_BYTES = 2 * 1024 * 1024; // 2MB 解码/传输负载
const CURSOR_MIN_SCALE = 0.5;
const CURSOR_MAX_SCALE = 4;

// Chromium 实际会回调的内置类型集合；custom 单独走位图校验。
const CURSOR_TYPES = new Set([
  'default', 'crosshair', 'pointer', 'text', 'hand', 'help', 'wait', 'progress',
  'move', 'not-allowed', 'cell', 'context-menu', 'alias', 'copy', 'none',
  'grab', 'grabbing', 'custom', 'zoom-in', 'zoom-out',
]);

const FALLBACK_TYPE = 'default';

function isValidType(type) {
  return typeof type === 'string' && CURSOR_TYPES.has(type);
}

// validateCustomImage 校验调用方读出的位图信息。要求正整数边长、边长不超上限、
// bytes 为非负有限整数且不超上限。width/height/bytes 任一缺失即视为不可信。
function validateCustomImage(image) {
  if (!image || typeof image !== 'object') return false;
  const { width, height, bytes } = image;
  if (!Number.isInteger(width) || !Number.isInteger(height)) return false;
  if (width <= 0 || height <= 0) return false;
  if (width > CURSOR_MAX_EDGE_PX || height > CURSOR_MAX_EDGE_PX) return false;
  if (!Number.isInteger(bytes) || bytes < 0) return false;
  if (bytes > CURSOR_MAX_IMAGE_BYTES) return false;
  return true;
}

function isValidScale(scale) {
  return typeof scale === 'number' && Number.isFinite(scale)
    && scale >= CURSOR_MIN_SCALE && scale <= CURSOR_MAX_SCALE;
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

function createCursorState(now) {
  return {
    times: [],
    applied: 0,
    held: 0,
    dropped: 0,
    lastType: '',
    lastAppliedAt: 0,
    cooldownUntil: 0,
    createdAt: now || 0,
  };
}

function resetForNavigation(state) {
  if (!state) return;
  state.times = [];
  state.lastType = '';
  state.lastAppliedAt = 0;
  state.cooldownUntil = 0;
}

// decideCursorChange 裁决一次 cursor-changed。
// 参数：type 字符串；image 仅 type==='custom' 时需要 {width,height,bytes}；
// scale 可选（默认 1）。返回 { action, reason, type }，drop 时 type 回落 default。
function decideCursorChange(state, type, image, scale, now) {
  if (!state) throw new TypeError('cursorguard: state required');
  const effScale = scale === undefined || scale === null ? 1 : scale;
  const counts = () => ({
    burstCount: countSince(state.times, now - CURSOR_BURST_WINDOW_MS),
    longCount: state.times.length, droppedTotal: state.dropped,
  });
  const fallback = (reason) => {
    state.dropped += 1;
    return { action: CURSOR_DROP, reason, type: FALLBACK_TYPE, ...counts() };
  };

  if (!isValidType(type)) return fallback(DROP_BAD_TYPE);
  if (!isValidScale(effScale)) return fallback(DROP_BAD_SCALE);
  if (type === 'custom' && !validateCustomImage(image)) return fallback(DROP_BAD_IMAGE);

  const inCooldownBefore = state.cooldownUntil > now;
  state.times.push(now);
  pruneOlderThan(state.times, now - CURSOR_LONG_WINDOW_MS);
  const burst = countSince(state.times, now - CURSOR_BURST_WINDOW_MS);
  let flood = null;
  if (burst > CURSOR_BURST_LIMIT || state.times.length > CURSOR_LONG_LIMIT) {
    state.cooldownUntil = now + CURSOR_COOLDOWN_MS;
    flood = { reason: DROP_FLOOD, burstCount: burst, longCount: state.times.length };
  }

  if (state.cooldownUntil > now || flood) {
    state.dropped += 1;
    return {
      action: CURSOR_DROP,
      reason: inCooldownBefore ? DROP_COOLDOWN : (flood ? flood.reason : DROP_COOLDOWN),
      type: FALLBACK_TYPE,
      burstCount: flood ? flood.burstCount : burst,
      longCount: flood ? flood.longCount : state.times.length,
      cooldownUntil: state.cooldownUntil, droppedTotal: state.dropped,
    };
  }
  if (state.cooldownUntil > 0 && state.cooldownUntil <= now) state.cooldownUntil = 0;

  if (type === state.lastType) {
    state.held += 1;
    return { action: CURSOR_HOLD, reason: HOLD_SAME, type, ...counts() };
  }
  if (now - state.lastAppliedAt < CURSOR_MIN_INTERVAL_MS && state.lastAppliedAt !== 0) {
    state.held += 1;
    return { action: CURSOR_HOLD, reason: HOLD_TOO_SOON, type, ...counts() };
  }

  state.applied += 1;
  state.lastType = type;
  state.lastAppliedAt = now;
  return { action: CURSOR_APPLY, reason: '', type, ...counts() };
}

function describeCursorReason(reason) {
  switch (reason) {
    case HOLD_SAME:
      return '光标类型未变化，已合并';
    case HOLD_TOO_SOON:
      return '光标类型变化过快，已合并';
    case DROP_BAD_TYPE:
      return '页面请求了未知类型的光标，已回落到默认光标';
    case DROP_BAD_IMAGE:
      return '自定义光标位图尺寸或体积超限，已回落到默认光标';
    case DROP_BAD_SCALE:
      return '自定义光标缩放比例越界，已回落到默认光标';
    case DROP_FLOOD:
      return '页面异常频繁切换光标（疑似抖动 DoS），冷却期内锁定默认光标';
    case DROP_COOLDOWN:
      return '光标抖动冷却期内的变更已回落为默认光标';
    default:
      return '光标变更';
  }
}

module.exports = {
  CURSOR_APPLY,
  CURSOR_HOLD,
  CURSOR_DROP,
  HOLD_SAME,
  HOLD_TOO_SOON,
  DROP_BAD_TYPE,
  DROP_BAD_IMAGE,
  DROP_BAD_SCALE,
  DROP_FLOOD,
  DROP_COOLDOWN,
  FALLBACK_TYPE,
  CURSOR_TYPES,
  CURSOR_MAX_EDGE_PX,
  CURSOR_MAX_IMAGE_BYTES,
  CURSOR_MIN_SCALE,
  CURSOR_MAX_SCALE,
  CURSOR_MIN_INTERVAL_MS,
  CURSOR_BURST_WINDOW_MS,
  CURSOR_BURST_LIMIT,
  CURSOR_LONG_WINDOW_MS,
  CURSOR_LONG_LIMIT,
  CURSOR_COOLDOWN_MS,
  isValidType,
  validateCustomImage,
  isValidScale,
  createCursorState,
  resetForNavigation,
  decideCursorChange,
  describeCursorReason,
};
