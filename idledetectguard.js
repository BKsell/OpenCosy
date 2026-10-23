'use strict';

// idledetectguard.js —— Idle Detection API（IdleDetector）后台空闲状态探测裁决内核。
//
// 威胁模型：
//   1. IdleDetector 能在用户"离开/未交互"时得到通知，被用来判断家里是否有人、
//      用户何时离开工位，配合摄像头/指纹做入室/社工时机选择；
//   2. 该能力需要 'idle-detection' 权限，但页面可在后台标签/最小化窗口持续运行，
//      把空闲事件外发做跨站在线状态画像；
//   3. 无手势请求权限 + 极短 threshold（秒级）最大化采样频率；
//   4. screenReader/静音等系统状态与空闲组合推断残障信息（敏感个人数据）；
//   5. 多个 detector 实例重复 start 做冗余上报。
//
// 纯逻辑：权限/上下文门、最小采样间隔、后台运行、实例数、活跃事件外发门。

const ID_DENY = 'deny';
const ID_ALLOW = 'allow';

const ID_REASON = Object.freeze({
  INSECURE_CONTEXT: 'id-insecure-context',
  BAD_ORIGIN: 'id-bad-origin',
  BLOCKED_ORIGIN: 'id-blocked-origin',
  PERMISSION_NOT_GRANTED: 'id-permission-not-granted',
  NO_GESTURE_PERMISSION_REQUEST: 'id-no-gesture-permission-request',
  BACKGROUND_FORBIDDEN: 'id-background-forbidden',
  THRESHOLD_TOO_SMALL: 'id-threshold-too-small',
  TOO_MANY_DETECTORS: 'id-too-many-detectors',
  START_THROTTLED: 'id-start-throttled',
  EXFIL_WHILE_HIDDEN: 'id-exfil-while-hidden',
});

function defaultIdlePolicy() {
  return {
    requireSecureContext: true,
    permissionGranted: false, // 默认未授予
    requireGestureForPermission: true,
    denyBackground: true,
    minThresholdMs: 60000, // 最小空闲判定间隔 60 秒
    maxDetectorsPerOrigin: 1,
    startMinIntervalMs: 5000,
    allowReportingWhileHidden: false,
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.indexOf('/') >= 0 || rest.indexOf('?') >= 0) return '';
  return scheme + '://' + rest.toLowerCase();
}

class IdleDetectGuard {
  constructor(policy) {
    this.policy = policy || defaultIdlePolicy();
    this.detectors = new Map();
    this.lastStart = new Map();
  }

  // decidePermissionRequest 裁决 navigator.permissions.request({name:'idle-detection'})。
  decidePermissionRequest(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { allowed: false, reason: ID_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { allowed: false, reason: ID_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { allowed: false, reason: ID_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { allowed: false, reason: ID_REASON.BLOCKED_ORIGIN };
    if (pol.requireGestureForPermission && ctx.hasUserGesture !== true) {
      return { allowed: false, reason: ID_REASON.NO_GESTURE_PERMISSION_REQUEST };
    }
    return { allowed: true, reason: '' };
  }

  // decideStart 裁决 new IdleDetector().start({threshold})。
  // ctx: {origin,isSecureContext,blocked,isBackground,isHidden,now}
  decideStart(ctx, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { allowed: false, reason: ID_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { allowed: false, reason: ID_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { allowed: false, reason: ID_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { allowed: false, reason: ID_REASON.BLOCKED_ORIGIN };
    if (!pol.permissionGranted) return { allowed: false, reason: ID_REASON.PERMISSION_NOT_GRANTED };
    if (pol.denyBackground && ctx.isBackground === true) {
      return { allowed: false, reason: ID_REASON.BACKGROUND_FORBIDDEN };
    }
    const threshold = options && typeof options.threshold === 'number' ? options.threshold : pol.minThresholdMs;
    if (threshold < pol.minThresholdMs) {
      return { allowed: false, reason: ID_REASON.THRESHOLD_TOO_SMALL };
    }
    if ((this.detectors.get(key) || 0) >= pol.maxDetectorsPerOrigin) {
      return { allowed: false, reason: ID_REASON.TOO_MANY_DETECTORS };
    }
    const now = ctx.now || 0;
    if (this.lastStart.has(key) && now - this.lastStart.get(key) < pol.startMinIntervalMs) {
      return { allowed: false, reason: ID_REASON.START_THROTTLED };
    }
    this.detectors.set(key, (this.detectors.get(key) || 0) + 1);
    this.lastStart.set(key, now);
    return { allowed: true, reason: '', effectiveThresholdMs: Math.max(threshold, pol.minThresholdMs) };
  }

  noteStop(origin) {
    const key = originKey(origin);
    this.detectors.set(key, Math.max(0, (this.detectors.get(key) || 1) - 1));
  }

  // decideReport 裁决是否允许把一次空闲变化外发（隐藏页签默认禁止）。
  decideReport(ctx) {
    if (!originKey(ctx && ctx.origin)) return { allowed: false, reason: ID_REASON.BAD_ORIGIN };
    if (!this.policy.allowReportingWhileHidden && ctx.isHidden === true) {
      return { allowed: false, reason: ID_REASON.EXFIL_WHILE_HIDDEN };
    }
    if (this.policy.denyBackground && ctx.isBackground === true) {
      return { allowed: false, reason: ID_REASON.EXFIL_WHILE_HIDDEN };
    }
    return { allowed: true, reason: '' };
  }
}

module.exports = {
  ID_ALLOW, ID_DENY, ID_REASON,
  defaultIdlePolicy, originKey, IdleDetectGuard,
};
