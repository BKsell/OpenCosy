'use strict';

// geolocationguard.js —— navigator.geolocation 的权限请求门、精度收敛与后台/
// 高频监听裁决内核（纯逻辑，不直接触碰 navigator，由注入层调用）。
//
// 威胁模型：
//   1. 高精度经纬度一旦给到第三方页面即长期可定位，且可与 IP/时区/传感器交叉
//      还原身份；广告/追踪页常在无手势、后台标签里静默 getCurrentPosition；
//   2. watchPosition 持续上报移动轨迹，频率不受控时等于实时追踪；
//   3. enableHighAccuracy 强制 GPS 级精度，普通天气/本地化场景根本不需要；
//   4. 非安全上下文、data:/sandbox 框架不应拿到任何位置；
//   5. 同一站短时间反复弹权限框做“疲劳轰炸”逼用户点允许。
//
// 本模块裁决“是否允许、允许到什么精度、以什么节奏上报”，并对返回坐标做可选
// 的模糊化（降低精度 + 量化），不接触真实 GPS 采集。

const GEO_DENY = 'deny';
const GEO_PROMPT = 'prompt';
const GEO_ALLOW_COARSE = 'allow-coarse';
const GEO_ALLOW_FINE = 'allow-fine';

const GEO_REASON = Object.freeze({
  INSECURE_CONTEXT: 'geo-insecure-context',
  BAD_ORIGIN: 'geo-bad-origin',
  NO_GESTURE: 'geo-no-user-gesture',
  THROTTLED: 'geo-prompt-throttled',
  BACKGROUND: 'geo-background-tab',
  UNTRUSTED_FRAME: 'geo-untrusted-frame',
  HIGH_ACCURACY_FORBIDDEN: 'geo-high-accuracy-not-permitted',
  WATCH_RATE_TOO_FAST: 'geo-watch-interval-too-short',
  ORIGIN_BLOCKED: 'geo-origin-blocked',
});

// 默认策略。
function defaultGeoPolicy() {
  return {
    requireSecureContext: true,
    requireUserGesture: true,
    denyBackground: true,
    allowIframes: false,
    promptMinIntervalMs: 60_000,
    coarseAccuracyMeters: 5000,     // 模糊后半径量级
    fineAccuracyFloorMeters: 50,    // 即使允许高精度，也不低于此半径
    minWatchIntervalMs: 5_000,
    maxWatchSessionsPerOrigin: 3,
  };
}

function parseOrigin(origin) {
  if (typeof origin !== 'string') return null;
  const idx = origin.indexOf('://');
  if (idx <= 0) return null;
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return null;
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.includes('/') || rest.includes('?') || rest.includes('#')) return null;
  return { scheme, rest };
}

// GeoPromptGate 记录每来源最近的权限请求时间，做节流。
class GeoPromptGate {
  constructor(policy) {
    this.policy = policy || defaultGeoPolicy();
    this.lastPromptAt = new Map(); // originKey -> ts
    this.watchCount = new Map();
  }

  originKey(origin) {
    const p = parseOrigin(origin);
    if (!p) return '';
    return p.scheme + '://' + p.rest.toLowerCase();
  }

  // decideRequest 裁决一次 getCurrentPosition/watchPosition 请求。
  // ctx: { origin, isSecureContext, hasUserGesture, isBackground, isTopFrame,
  //        highAccuracy, blocked, now }
  decideRequest(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') {
      return { decision: GEO_DENY, reason: GEO_REASON.BAD_ORIGIN };
    }
    if (pol.requireSecureContext && !ctx.isSecureContext) {
      return { decision: GEO_DENY, reason: GEO_REASON.INSECURE_CONTEXT };
    }
    const key = this.originKey(ctx.origin);
    if (!key) {
      return { decision: GEO_DENY, reason: GEO_REASON.BAD_ORIGIN };
    }
    if (ctx.blocked === true) {
      return { decision: GEO_DENY, reason: GEO_REASON.ORIGIN_BLOCKED };
    }
    if (pol.allowIframes === false && ctx.isTopFrame === false) {
      return { decision: GEO_DENY, reason: GEO_REASON.UNTRUSTED_FRAME };
    }
    if (pol.denyBackground && ctx.isBackground === true) {
      return { decision: GEO_DENY, reason: GEO_REASON.BACKGROUND };
    }
    if (pol.requireUserGesture && ctx.hasUserGesture !== true) {
      return { decision: GEO_DENY, reason: GEO_REASON.NO_GESTURE };
    }

    // 权限弹窗节流。
    const now = ctx.now || 0;
    const last = this.lastPromptAt.get(key) || 0;
    if (now - last < pol.promptMinIntervalMs) {
      return { decision: GEO_PROMPT, reason: GEO_REASON.THROTTLED };
    }

    if (ctx.highAccuracy === true) {
      return { decision: GEO_PROMPT, reason: GEO_REASON.HIGH_ACCURACY_FORBIDDEN, granted: false };
    }
    this.lastPromptAt.set(key, now);
    return { decision: GEO_ALLOW_COARSE, reason: '' };
  }

  // grantFine 在用户明确同意高精度后调用，记录并返回高精度授权。
  grantFine(ctx) {
    const key = this.originKey(ctx && ctx.origin);
    if (!key) return { decision: GEO_DENY, reason: GEO_REASON.BAD_ORIGIN };
    this.lastPromptAt.set(key, (ctx && ctx.now) || 0);
    return { decision: GEO_ALLOW_FINE, reason: '' };
  }

  // registerWatch 注册一个持续监听会话，校验每来源会话数与最小间隔。
  registerWatch(ctx, desiredIntervalMs) {
    const key = this.originKey(ctx && ctx.origin);
    if (!key) return { ok: false, reason: GEO_REASON.BAD_ORIGIN };
    const n = this.watchCount.get(key) || 0;
    if (n >= this.policy.maxWatchSessionsPerOrigin) {
      return { ok: false, reason: GEO_REASON.WATCH_RATE_TOO_FAST };
    }
    let interval = Number(desiredIntervalMs);
    if (!Number.isFinite(interval) || interval < 0) interval = 0;
    if (interval !== 0 && interval < this.policy.minWatchIntervalMs) {
      interval = this.policy.minWatchIntervalMs;
    }
    this.watchCount.set(key, n + 1);
    return { ok: true, intervalMs: interval, sessions: n + 1 };
  }

  releaseWatch(origin) {
    const key = this.originKey(origin);
    const n = this.watchCount.get(key) || 0;
    if (n <= 1) this.watchCount.delete(key);
    else this.watchCount.set(key, n - 1);
  }
}

// blurCoordinate 对一个坐标做量化模糊。
// radiusMeters 越大网格越粗；纬度方向 1 度约 111320 米。
function blurCoordinate(lat, lon, radiusMeters) {
  if (typeof lat !== 'number' || typeof lon !== 'number' || !Number.isFinite(lat) || !Number.isFinite(lon)) {
    return null;
  }
  if (!(lat >= -90 && lat <= 90) || !(lon >= -180 && lon <= 180)) return null;
  let r = Number(radiusMeters);
  if (!Number.isFinite(r) || r <= 0) r = defaultGeoPolicy().coarseAccuracyMeters;
  const latStep = r / 111320;
  const qLat = Math.round(lat / latStep) * latStep;
  const cos = Math.cos(qLat * Math.PI / 180);
  const lonStep = Math.abs(cos) < 1e-6 ? latStep : r / (111320 * Math.max(Math.abs(cos), 1e-6));
  const qLon = Math.round(lon / lonStep) * lonStep;
  return {
    latitude: qLat,
    longitude: qLon,
    accuracy: r,
    blurred: true,
  };
}

// applyDecisionToPosition 按裁决把高精度坐标收敛为可返回给页面的坐标。
function applyDecisionToPosition(decision, pos, policy) {
  const pol = policy || defaultGeoPolicy();
  if (!pos || typeof pos !== 'object') return pos;
  if (decision === GEO_ALLOW_FINE) {
    if (typeof pos.accuracy === 'number' && pos.accuracy < pol.fineAccuracyFloorMeters) {
      return Object.assign({}, pos, { accuracy: pol.fineAccuracyFloorMeters });
    }
    return pos;
  }
  if (decision === GEO_ALLOW_COARSE) {
    const b = blurCoordinate(pos.latitude, pos.longitude, pol.coarseAccuracyMeters);
    if (!b) return pos;
    return Object.assign({}, pos, b);
  }
  return pos;
}

module.exports = {
  GEO_DENY, GEO_PROMPT, GEO_ALLOW_COARSE, GEO_ALLOW_FINE, GEO_REASON,
  defaultGeoPolicy, parseOrigin, GeoPromptGate, blurCoordinate, applyDecisionToPosition,
};
