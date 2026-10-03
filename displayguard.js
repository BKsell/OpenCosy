'use strict';

// displayguard.js —— 屏幕共享（getDisplayMedia）与蓝牙设备选择的默认拒绝策略内核。
//
// 威胁模型：
//   普通摄像头/麦克风走 setPermissionRequestHandler，已在 main.js 收口；但有两条
//   “设备/画面采集”通道不走那个回调：
//     1) navigator.mediaDevices.getDisplayMedia() 触发的是 session 的
//        setDisplayMediaRequestHandler。不设置时，嵌入式 WebContentsView 没有可靠的
//        系统桌面选择器兜底，不同 Electron 版本行为不一致，存在“静默拿到某块屏幕/
//        窗口画面”的风险——网页一旦诱导成功即可长时间录屏，泄露其它标签页/桌面内容。
//     2) navigator.bluetooth.requestDevice() 触发 webContents 的 'select-bluetooth-device'
//        事件。该事件若无人监听，部分平台会“自动选中枚举到的第一个蓝牙设备”并继续
//        配对，等于把本机蓝牙设备暴露给网页。
//
//   浏览器场景下网页没有正当理由录制整屏或直连蓝牙设备，因此本内核给出“默认拒绝”的
//   纯判定：把 Electron 回调入参归一成稳定决策，main.js 只负责据此 deny / callback('')。
//   预留 isPrivilegedInternal（内部 cosy:/file 外壳）判断位，当前即便内部也不放行屏幕
//   共享，保持最小权限；未来若要做可信白名单，只改本内核即可。

const DISPLAY_DECISION_DENY = 'deny';
const BLUETOOTH_DECISION_CANCEL = 'cancel';

// 规范化 mediaTypes：去重、限定为 Chromium 会给出的 screen/window/audio 三类。
function normalizeMediaTypes(mediaTypes) {
  const known = new Set(['screen', 'window', 'audio']);
  const out = [];
  if (!Array.isArray(mediaTypes)) return out;
  for (const raw of mediaTypes) {
    const t = String(raw || '').toLowerCase().trim();
    if (known.has(t) && !out.includes(t)) out.push(t);
  }
  return out;
}

// 安全地取来源 origin，失败返回空串（不抛异常）。
function originFromUrl(rawUrl) {
  try {
    return new URL(rawUrl || '').origin;
  } catch {
    return '';
  }
}

// decideDisplayMedia 判定一次屏幕共享请求。当前策略恒为拒绝，但给出稳定 reason，
// 便于安全面板区分“只要音频”“要画面”“畸形请求”等情形。
//   details: { frame: {url,urlLeft}, mediaTypes: string[] }
// 返回 { decision, reason, origin, mediaTypes }。
function decideDisplayMedia(details) {
  const d = details || {};
  const frame = d.frame || {};
  const origin = originFromUrl(frame.url || frame.urlLeft || '');
  const mediaTypes = normalizeMediaTypes(d.mediaTypes);

  if (mediaTypes.length === 0) {
    return { decision: DISPLAY_DECISION_DENY, reason: 'display-malformed', origin, mediaTypes };
  }
  const wantsVideo = mediaTypes.includes('screen') || mediaTypes.includes('window');
  if (!wantsVideo && mediaTypes.includes('audio')) {
    // 只要“系统音频”也可能伴随屏幕音频采集，统一拒绝并单独标记，避免被当成普通麦克风。
    return { decision: DISPLAY_DECISION_DENY, reason: 'display-audio-only', origin, mediaTypes };
  }
  return { decision: DISPLAY_DECISION_DENY, reason: 'display-capture', origin, mediaTypes };
}

// isDisplayMediaHandlerAvailable 做能力探测包装，便于在不支持该 API 的旧版 Electron
// 上安全跳过（main.js 调用前判断）。
function isDisplayMediaHandlerAvailable(session) {
  return !!(session && typeof session.setDisplayMediaRequestHandler === 'function');
}

// decideBluetoothSelection 判定一次蓝牙设备选择。policy 恒为 cancel：不自动选任何
// 设备。返回 { decision, origin, deviceCount }。
function decideBluetoothSelection(details) {
  const d = details || {};
  const origin = originFromUrl(d.url || '');
  const devices = Array.isArray(d.devices) ? d.devices : [];
  return {
    decision: BLUETOOTH_DECISION_CANCEL,
    reason: 'bluetooth-auto-select',
    origin,
    deviceCount: devices.length,
  };
}

module.exports = {
  DISPLAY_DECISION_DENY,
  BLUETOOTH_DECISION_CANCEL,
  normalizeMediaTypes,
  originFromUrl,
  decideDisplayMedia,
  decideBluetoothSelection,
  isDisplayMediaHandlerAvailable,
};
