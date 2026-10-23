'use strict';

// batteryguard.js —— navigator.getBattery 与 navigator.connection 信息泄漏裁决内核。
//
// 威胁模型：
//   1. Battery Status API 的 level/charging/chargingTime/dischargingTime 组合是
//      跨站稳定指纹（早期 Tor 浏览器为此直接禁用该 API），可在清除 Cookie 后再识别；
//   2. 放电时间 + 电量百分比熵很高，单页面读取即可加入追踪向量；
//   3. Network Information API 的 effectiveType/rtt/downlink/saveData 暴露网络质量，
//      既做指纹又可被用于差异化钓鱼（对弱网下发更省流量的假登录页）；
//   4. 高频监听 levelchange/change 事件做在线行为画像；
//   5. 后台标签页持续读取，构建设备使用时间线。
//
// 本模块给出读取门、量化（降熵）策略与监听频控。纯逻辑。

const BG_DENY = 'deny';
const BG_ALLOW = 'allow';
const BG_REDACT = 'redact';

const BG_REASON = Object.freeze({
  INSECURE_CONTEXT: 'bg-insecure-context',
  BAD_ORIGIN: 'bg-bad-origin',
  BLOCKED_ORIGIN: 'bg-blocked-origin',
  BACKGROUND_READ: 'bg-background-read',
  READ_THROTTLED: 'bg-read-throttled',
  LISTEN_THROTTLED: 'bg-listen-throttled',
  TOO_MANY_LISTENERS: 'bg-too-many-listeners',
  HIGH_PRECISION_FORBIDDEN: 'bg-high-precision-forbidden',
});

function defaultBatteryPolicy() {
  return {
    requireSecureContext: false,
    denyBackground: true,
    readMinIntervalMs: 1000,
    listenMinIntervalMs: 2000,
    maxListenersPerOrigin: 4,
    // 降熵：电量量化到 0.25 档，时间量化到固定步长，布尔充放电状态可关。
    quantizeLevel: true,
    levelStep: 0.25,
    quantizeTime: true,
    timeStepMs: 600000, // 10 分钟
    exposeChargingState: true,
    exposeNetworkRtt: false,
    networkDownlinkStepMbps: 1,
    exposeSaveData: true,
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

function clamp01(x) {
  if (typeof x !== 'number' || !isFinite(x)) return 0;
  if (x < 0) return 0;
  if (x > 1) return 1;
  return x;
}

// quantizeLevel 把电量降到有限档位：0,0.25,0.5,0.75,1。
function quantizeLevel(level, step) {
  const v = clamp01(level);
  const s = step > 0 ? step : 0.25;
  return Math.round(v / s) * s;
}

// quantizeTimeMs 把秒级时间戳/时长量化到固定步长；Infinity（充满/耗尽未知）保留为 Infinity。
function quantizeTimeMs(ms, step) {
  if (ms === Infinity || ms === null || ms === undefined) return Infinity;
  if (typeof ms !== 'number' || !isFinite(ms) || ms < 0) return Infinity;
  const s = step > 0 ? step : 600000;
  return Math.floor(ms / s) * s;
}

// redactBattery 按策略输出降熵后的电池快照。
function redactBattery(raw, policy) {
  const p = policy || defaultBatteryPolicy();
  const out = {};
  const level = p.quantizeLevel ? quantizeLevel(raw.level, p.levelStep) : clamp01(raw.level);
  out.level = level;
  if (p.exposeChargingState) {
    out.charging = raw.charging === true;
    if (raw.charging === true) {
      out.chargingTime = p.quantizeTime ? quantizeTimeMs(raw.chargingTime, p.timeStepMs) : raw.chargingTime;
    } else {
      out.dischargingTime = p.quantizeTime ? quantizeTimeMs(raw.dischargingTime, p.timeStepMs) : raw.dischargingTime;
    }
  }
  return out;
}

// redactNetwork 按策略输出降熵后的网络信息。
function redactNetwork(raw, policy) {
  const p = policy || defaultBatteryPolicy();
  const out = { effectiveType: typeof raw.effectiveType === 'string' ? raw.effectiveType : 'unknown' };
  if (p.exposeSaveData) out.saveData = raw.saveData === true;
  if (p.exposeNetworkRtt) {
    out.rtt = typeof raw.rtt === 'number' && isFinite(raw.rtt) ? Math.round(raw.rtt / 50) * 50 : 0;
  }
  if (typeof raw.downlink === 'number' && isFinite(raw.downlink)) {
    out.downlink = Math.round(raw.downlink / p.networkDownlinkStepMbps) * p.networkDownlinkStepMbps;
  }
  return out;
}

class BatteryGuard {
  constructor(policy) {
    this.policy = policy || defaultBatteryPolicy();
    this.lastRead = new Map();
    this.lastListen = new Map();
    this.listenerCount = new Map();
  }

  _base(ctx, map, interval, reason) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { allowed: false, reason: BG_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { allowed: false, reason: BG_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { allowed: false, reason: BG_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { allowed: false, reason: BG_REASON.BLOCKED_ORIGIN };
    if (pol.denyBackground && ctx.isBackground === true) {
      return { allowed: false, reason: BG_REASON.BACKGROUND_READ };
    }
    const now = ctx.now || 0;
    if (map.has(key) && now - map.get(key) < interval) {
      return { allowed: false, reason };
    }
    return { allowed: true, key, now };
  }

  decideRead(ctx) {
    const r = this._base(ctx, this.lastRead, this.policy.readMinIntervalMs, BG_REASON.READ_THROTTLED);
    if (!r.allowed) return r;
    this.lastRead.set(r.key, r.now);
    return { allowed: true, decision: this.policy.quantizeLevel ? BG_REDACT : BG_ALLOW, reason: '' };
  }

  decideAddListener(ctx) {
    const pol = this.policy;
    const r = this._base(ctx, this.lastListen, pol.listenMinIntervalMs, BG_REASON.LISTEN_THROTTLED);
    if (!r.allowed) return r;
    const count = this.listenerCount.get(r.key) || 0;
    if (count >= pol.maxListenersPerOrigin) {
      return { allowed: false, reason: BG_REASON.TOO_MANY_LISTENERS };
    }
    this.lastListen.set(r.key, r.now);
    this.listenerCount.set(r.key, count + 1);
    return { allowed: true, reason: '' };
  }

  noteRemoveListener(origin) {
    const key = originKey(origin);
    this.listenerCount.set(key, Math.max(0, (this.listenerCount.get(key) || 0) - 1));
  }
}

module.exports = {
  BG_ALLOW, BG_DENY, BG_REDACT, BG_REASON,
  defaultBatteryPolicy, originKey, quantizeLevel, quantizeTimeMs,
  redactBattery, redactNetwork, BatteryGuard,
};
