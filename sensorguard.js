'use strict';

// sensorguard.js —— DeviceMotion / DeviceOrientation（及通用传感器）监听的
// 手势门、后台拒绝、采样率收敛与每源监听配额内核。
//
// 威胁模型：
//   iOS 13 起要求 DeviceMotionEvent.requestPermission 且需用户手势；桌面 Chromium
//   对部分传感器仍较宽松。加速度/陀螺仪/姿态数据可被用于：
//     1. 无手势静默采集，推断行走、敲击、设备姿态，做跨站指纹与行为追踪；
//     2. 后台标签持续监听（页面不可见仍收事件），持续耗电并泄漏环境运动；
//     3. 高频采样（requestAnimationFrame 级，>60Hz）还原更细粒度动作甚至语音震动；
//     4. 单页注册大量监听句柄做事件洪泛拖垮主进程。
//
// 本模块不替换事件 API，只裁决“能否注册、按什么最低采样间隔下发”，并提供
// 事件节流门（调用方在分发事件前过 shouldEmit）。

const SENSOR_DENY = 'deny';
const SENSOR_ALLOW = 'allow';

const SENSOR_REASON = Object.freeze({
  INSECURE_CONTEXT: 'sensor-insecure-context',
  BAD_ORIGIN: 'sensor-bad-origin',
  NO_GESTURE: 'sensor-no-user-gesture',
  PERMISSION_DENIED: 'sensor-permission-denied',
  BACKGROUND: 'sensor-background-tab',
  UNTRUSTED_FRAME: 'sensor-untrusted-frame',
  UNKNOWN_SENSOR: 'sensor-unknown-type',
  TOO_MANY_LISTENERS: 'sensor-too-many-listeners',
  RATE_TOO_FAST: 'sensor-sample-rate-too-fast',
  ORIGIN_BLOCKED: 'sensor-origin-blocked',
});

// 受管传感器类型（白名单，未知类型默认拒绝，防止用冷门事件绕过）。
const KNOWN_SENSORS = Object.freeze({
  devicemotion: { minIntervalMs: 40, backgroundAllowed: false, needsGesture: true },
  deviceorientation: { minIntervalMs: 80, backgroundAllowed: false, needsGesture: true },
  deviceorientationabsolute: { minIntervalMs: 80, backgroundAllowed: false, needsGesture: true },
  devicelight: { minIntervalMs: 200, backgroundAllowed: false, needsGesture: false },
  deviceproximity: { minIntervalMs: 200, backgroundAllowed: false, needsGesture: false },
});

function defaultSensorPolicy() {
  return {
    requireSecureContext: true,
    allowIframes: false,
    denyBackground: true,
    maxListenersPerOriginPerType: 4,
    permissionState: 'prompt', // granted / denied / prompt
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.includes('/') || rest.includes('?') || rest.includes('#')) return '';
  return scheme + '://' + rest.toLowerCase();
}

class SensorGuard {
  constructor(policy) {
    this.policy = policy || defaultSensorPolicy();
    // originKey -> sensorType -> count
    this.listeners = new Map();
    // originKey -> sensorType -> lastEmitTs
    this.lastEmit = new Map();
  }

  _bucket(map, key) {
    let m = map.get(key);
    if (!m) { m = new Map(); map.set(key, m); }
    return m;
  }

  // canAddListener 裁决是否允许注册一个传感器监听。
  // ctx: { origin, isSecureContext, hasUserGesture, isBackground, isTopFrame,
  //        sensorType, blocked }
  canAddListener(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') {
      return { allowed: false, decision: SENSOR_DENY, reason: SENSOR_REASON.BAD_ORIGIN };
    }
    const spec = KNOWN_SENSORS[String(ctx.sensorType).toLowerCase()];
    if (!spec) {
      return { allowed: false, decision: SENSOR_DENY, reason: SENSOR_REASON.UNKNOWN_SENSOR };
    }
    if (pol.requireSecureContext && !ctx.isSecureContext) {
      return { allowed: false, decision: SENSOR_DENY, reason: SENSOR_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { allowed: false, decision: SENSOR_DENY, reason: SENSOR_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) {
      return { allowed: false, decision: SENSOR_DENY, reason: SENSOR_REASON.ORIGIN_BLOCKED };
    }
    if (pol.permissionState === 'denied') {
      return { allowed: false, decision: SENSOR_DENY, reason: SENSOR_REASON.PERMISSION_DENIED };
    }
    if (!pol.allowIframes && ctx.isTopFrame === false) {
      return { allowed: false, decision: SENSOR_DENY, reason: SENSOR_REASON.UNTRUSTED_FRAME };
    }
    if (pol.denyBackground && !spec.backgroundAllowed && ctx.isBackground === true) {
      return { allowed: false, decision: SENSOR_DENY, reason: SENSOR_REASON.BACKGROUND };
    }
    if (spec.needsGesture && pol.permissionState !== 'granted' && ctx.hasUserGesture !== true) {
      return { allowed: false, decision: SENSOR_DENY, reason: SENSOR_REASON.NO_GESTURE };
    }
    const cnt = this._bucket(this.listeners, key).get(ctx.sensorType) || 0;
    if (cnt >= pol.maxListenersPerOriginPerType) {
      return { allowed: false, decision: SENSOR_DENY, reason: SENSOR_REASON.TOO_MANY_LISTENERS };
    }
    return {
      allowed: true, decision: SENSOR_ALLOW, reason: '',
      minIntervalMs: spec.minIntervalMs,
    };
  }

  addListener(ctx) {
    const v = this.canAddListener(ctx);
    if (!v.allowed) return v;
    const key = originKey(ctx.origin);
    const b = this._bucket(this.listeners, key);
    b.set(ctx.sensorType, (b.get(ctx.sensorType) || 0) + 1);
    return v;
  }

  removeListener(origin, sensorType) {
    const key = originKey(origin);
    const b = this.listeners.get(key);
    if (!b) return;
    const n = b.get(sensorType) || 0;
    if (n <= 1) b.delete(sensorType);
    else b.set(sensorType, n - 1);
  }

  // shouldEmit 为事件分发做采样节流。返回 true 表示这一帧可以下发给页面。
  shouldEmit(origin, sensorType, now) {
    const spec = KNOWN_SENSORS[String(sensorType).toLowerCase()];
    if (!spec) return false;
    const key = originKey(origin);
    if (!key) return false;
    const b = this._bucket(this.lastEmit, key);
    const prev = b.get(sensorType);
    const last = prev === undefined ? -Infinity : prev;
    if (now - last < spec.minIntervalMs) return false;
    b.set(sensorType, now);
    return true;
  }

  // pauseOrigin 在标签切到后台时调用：清空待发时间窗，恢复后重新节流。
  resetEmitClock(origin) {
    this.lastEmit.delete(originKey(origin));
  }

  listenerCount(origin, sensorType) {
    const b = this.listeners.get(originKey(origin));
    return b ? (b.get(sensorType) || 0) : 0;
  }
}

// quantizeSensorReading 对下发给页面的数值做量化，降低指纹/动作还原粒度。
function quantizeSensorReading(value, step) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return value;
  let s = Number(step);
  if (!Number.isFinite(s) || s <= 0) return value;
  return Math.round(value / s) * s;
}

module.exports = {
  SENSOR_DENY, SENSOR_ALLOW, SENSOR_REASON, KNOWN_SENSORS,
  defaultSensorPolicy, originKey, SensorGuard, quantizeSensorReading,
};
