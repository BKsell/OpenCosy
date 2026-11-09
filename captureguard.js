'use strict';

// captureguard.js —— screen-capture-changed 事件的纯逻辑守卫内核。
//
// 威胁模型：
//   Electron 在某个 webContents 开始 / 停止“屏幕 / 窗口 / 标签页捕获”（getDisplayMedia、
//   标签页投屏、WebRTC 收流）时触发 'screen-capture-changed'。OpenCosy 此前完全没有
//   接线这个事件：
//     1) 虽然 setDisplayMediaRequestHandler 默认拒绝屏幕共享，但 WebRTC tab-capture、
//        扩展接口、或未来策略放宽都可能让某个标签真的进入“正在捕获”状态，用户却没有
//        任何感知（没有红点 / 没有安全事件）；
//     2) 恶意页面可高速 start/stop 切换捕获句柄制造事件风暴，刷爆审计与 UI 通知；
//     3) captureInfo 形态畸形（id 非法、hasAudio 非布尔）可能是内部状态被污染的信号。
//
//   本内核归一化事件流，识别“进入捕获 / 离开捕获 / 句柄替换”，对任何进入“捕获中”
//   的标签都产出显式信号（main.js 据此亮红点 / 留痕），并对高频切换做冷却。纯函数。

const CAPTURE_IDLE = 'idle';       // 当前无捕获
const CAPTURE_ACTIVE = 'active';   // 正在捕获
const CAPTURE_NONE = '';           // Electron 用空字符串 id 表示“停止捕获”

const CAPTURE_PASS = 'pass';
const CAPTURE_SIGNAL = 'signal';   // 状态切换，需要 UI/审计感知
const CAPTURE_DROP = 'drop';       // 畸形 / 洪泛，丢弃该事件

// 事件切换阈值：正常的一次屏幕共享只会 start 一次、stop 一次。这里给极宽上限：
// 5 秒内最多 16 次句柄切换、60 秒内最多 60 次，超过即判定为切换风暴，冷却 10 秒。
const CAPTURE_BURST_WINDOW_MS = 5000;
const CAPTURE_BURST_MAX = 16;
const CAPTURE_LONG_WINDOW_MS = 60000;
const CAPTURE_LONG_MAX = 60;
const CAPTURE_COOLDOWN_MS = 10000;

// 捕获 id 的长度上限：Chromium 的 capture id 通常是短整数串 / 短 token。
const CAPTURE_MAX_ID_CHARS = 256;

function isValidCaptureId(id) {
  if (id === CAPTURE_NONE) return true; // 空 id 表示停止，是合法信号。
  if (typeof id !== 'string') return false;
  if (id.length === 0 || id.length > CAPTURE_MAX_ID_CHARS) return false;
  for (let i = 0; i < id.length; i++) {
    const c = id.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return false;
  }
  return true;
}

// normalizeCaptureInfo 归一化 Electron 的 captureInfo（不同版本字段不稳定）。
// 只提取可安全使用的形态：{ hasAudio: boolean, hasVideo: boolean }。
function normalizeCaptureInfo(info) {
  const o = info && typeof info === 'object' ? info : {};
  return {
    hasAudio: o.hasAudio === true,
    hasVideo: o.hasVideo !== false, // 缺省时屏幕捕获默认带画面，按 true 处理更保守。
  };
}

function createCaptureState(now) {
  return {
    status: CAPTURE_IDLE,
    activeId: CAPTURE_NONE,
    since: now || 0,
    burstStart: -1,
    burstCount: 0,
    longStart: -1,
    longCount: 0,
    cooldownUntil: 0,
    transitions: 0,
  };
}

function resetForNavigation(st, now) {
  if (!st) return;
  st.status = CAPTURE_IDLE;
  st.activeId = CAPTURE_NONE;
  st.since = now || 0;
  st.burstStart = -1;
  st.burstCount = 0;
  st.longStart = -1;
  st.longCount = 0;
  st.cooldownUntil = 0;
}

function admitTransition(st, now) {
  if (now < st.cooldownUntil) return false;
  if (st.burstStart < 0 || now - st.burstStart > CAPTURE_BURST_WINDOW_MS) {
    st.burstStart = now;
    st.burstCount = 0;
  }
  if (st.longStart < 0 || now - st.longStart > CAPTURE_LONG_WINDOW_MS) {
    st.longStart = now;
    st.longCount = 0;
  }
  st.burstCount += 1;
  st.longCount += 1;
  if (st.burstCount > CAPTURE_BURST_MAX || st.longCount > CAPTURE_LONG_MAX) {
    st.cooldownUntil = now + CAPTURE_COOLDOWN_MS;
    st.burstStart = -1;
    st.burstCount = 0;
    st.longStart = -1;
    st.longCount = 0;
    return false;
  }
  return true;
}

// evaluateCaptureChange 归一一次 screen-capture-changed 事件。
//   id：Electron 给的捕获句柄 id，空串表示停止。
//   info：captureInfo（可空）。
// 返回 { action, phase, id, hasAudio, hasVideo, reasons }。
//   phase: 'started' | 'stopped' | 'replaced' | 'unchanged'
function evaluateCaptureChange(st, id, info, now) {
  const cinfo = normalizeCaptureInfo(info);
  if (!isValidCaptureId(id)) {
    return {
      action: CAPTURE_DROP, phase: 'unchanged', id: CAPTURE_NONE,
      hasAudio: cinfo.hasAudio, hasVideo: cinfo.hasVideo, reasons: ['bad-capture-id'],
    };
  }

  const stopping = id === CAPTURE_NONE;
  // 幂等：已是空闲又收到停止，或同一 id 重复上报，都不算切换（不计数、不通知）。
  if (stopping && st.status === CAPTURE_IDLE) {
    return {
      action: CAPTURE_PASS, phase: 'unchanged', id: CAPTURE_NONE,
      hasAudio: false, hasVideo: false, reasons: [],
    };
  }
  if (!stopping && st.status === CAPTURE_ACTIVE && id === st.activeId) {
    return {
      action: CAPTURE_PASS, phase: 'unchanged', id,
      hasAudio: cinfo.hasAudio, hasVideo: cinfo.hasVideo, reasons: [],
    };
  }

  if (!admitTransition(st, now)) {
    return {
      action: CAPTURE_DROP, phase: 'unchanged', id: CAPTURE_NONE,
      hasAudio: cinfo.hasAudio, hasVideo: cinfo.hasVideo, reasons: ['capture-flood'],
    };
  }
  st.transitions += 1;

  let phase;
  if (stopping) {
    phase = 'stopped';
    st.status = CAPTURE_IDLE;
    st.activeId = CAPTURE_NONE;
    st.since = 0;
  } else if (st.status === CAPTURE_ACTIVE) {
    phase = 'replaced'; // 未先停止就换了句柄：异常但仍按“持续捕获中”处理。
    st.activeId = id;
    st.since = now;
  } else {
    phase = 'started';
    st.status = CAPTURE_ACTIVE;
    st.activeId = id;
    st.since = now;
  }

  return {
    action: CAPTURE_SIGNAL, phase, id: stopping ? CAPTURE_NONE : id,
    hasAudio: cinfo.hasAudio, hasVideo: cinfo.hasVideo,
    reasons: phase === 'replaced' ? ['capture-handle-replaced'] : [],
  };
}

module.exports = {
  CAPTURE_IDLE,
  CAPTURE_ACTIVE,
  CAPTURE_NONE,
  CAPTURE_PASS,
  CAPTURE_SIGNAL,
  CAPTURE_DROP,
  CAPTURE_BURST_MAX,
  CAPTURE_LONG_MAX,
  CAPTURE_COOLDOWN_MS,
  CAPTURE_MAX_ID_CHARS,
  isValidCaptureId,
  normalizeCaptureInfo,
  createCaptureState,
  resetForNavigation,
  admitTransition,
  evaluateCaptureChange,
};
