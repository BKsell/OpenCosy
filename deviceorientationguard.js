'use strict';

// deviceorientationguard.js —— DeviceMotion/DeviceOrientation 指纹闸门。
//
// 这两个 API 不需要权限就能读加速度计/陀螺仪，是网页指纹库的常客。
// Electron 壳里把它们的可用性收敛成策略：默认只在用户手势后、且页面
// https 时才暴露。

// decideSensorAccess 入参：
//   isSecureContext  布尔
//   hasUserGesture   布尔
//   origin           调用方 origin
//   policy           'allow' | 'deny-with-ios-hint' | 'block-all'
// 返回 { action:'allow'|'deny', silent:boolean, reason }
function decideSensorAccess(opts) {
  const o = opts || {};
  const policy = String(o.policy || 'deny-with-ios-hint');
  if (policy === 'block-all') {
    return { action: 'deny', silent: true, reason: 'block-all' };
  }
  if (!o.isSecureContext) {
    return { action: 'deny', silent: true, reason: 'insecure-context' };
  }
  if (!o.hasUserGesture) {
    // iOS 风格：不请求就静默空数据，触发指纹收集失败。
    return { action: 'deny', silent: true, reason: 'needs-gesture' };
  }
  return { action: 'allow', silent: false, reason: 'ok' };
}

// shouldScrubSensorEvents 是否把传感器事件的高频采样压成低频（降噪+反指纹）。
function shouldScrubSensorEvents(policy) {
  return String(policy || 'deny-with-ios-hint') !== 'allow';
}

module.exports = {
  decideSensorAccess,
  shouldScrubSensorEvents,
};
