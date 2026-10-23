'use strict';

// timingguard.js —— 高分辨率计时与跨源共享内存侧信道缓解内核。
//
// 威胁模型：
//   1. performance.now() 亚毫秒/亚微秒精度可被用于 Spectre 类时序攻击、缓存计时、
//      ASLR 推断；浏览器（Tor/Firefox）普遍把它降到 ~100ms/1ms/5ms 量级；
//   2. event.timeStamp、performance.timeOrigin 同样提供高精度时钟；
//   3. 嵌套 setTimeout 历史上会被 clamp 到最小 4ms，页面用大量 0ms 定时器做高频
//      计时侧信道与 busy 探测；
//   4. SharedArrayBuffer 要求 crossOriginIsolated（COOP+COEP），否则页面拿到 SAB
//      可搭建高带宽跨线程计时通道；
//   5. performance.memory（Chromium）暴露 JS 堆占用，用于堆风水与指纹。
//
// 本模块做时间量化、定时器最小值裁决、跨源隔离门与内存字段裁剪。纯逻辑。

const TG_ALLOW = 'allow';
const TG_DENY = 'deny';

const TG_REASON = Object.freeze({
  NOT_CROSS_ORIGIN_ISOLATED: 'tg-not-cross-origin-isolated',
  NESTED_TIMER_CLAMPED: 'tg-nested-timer-clamped',
  MEMORY_FIELD_REDACTED: 'tg-memory-field-redacted',
  TIMER_FLOOD: 'tg-timer-flood',
});

function defaultTimingPolicy() {
  return {
    // 时间量化步长（毫秒）。5ms 为现代浏览器常见折中。
    nowStepMs: 5,
    timeOriginStepMs: 5,
    addPerOriginJitter: true,
    jitterMaxMs: 4,
    minTimeoutMs: 1,
    nestedTimeoutFloorMs: 4,
    nestedDepthThreshold: 5,
    maxActiveTimersPerOrigin: 256,
    requireIsolationForSab: true,
    exposePerformanceMemory: false,
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

// 每 origin 一个确定性伪随机抖动（同会话内稳定，避免每次量化乱跳）。
// 用简单字符串混洗得到 0..max 的整数，不引入 Math.random 的不可测性。
function stableJitter(key, max) {
  let h = 2166136261;
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const u = h >>> 0;
  return max <= 0 ? 0 : u % (max + 1);
}

// quantizeNow 把高精度时间戳量化到步长，可选叠加每 origin 固定抖动。
function quantizeNow(origin, hiResMs, policy) {
  const p = policy || defaultTimingPolicy();
  if (typeof hiResMs !== 'number' || !isFinite(hiResMs)) return 0;
  let v = Math.floor(hiResMs / p.nowStepMs) * p.nowStepMs;
  if (p.addPerOriginJitter) {
    v += stableJitter(originKey(origin) || 'unknown', p.jitterMaxMs);
  }
  return v;
}

function quantizeTimeOrigin(origin, hiResMs, policy) {
  const p = policy || defaultTimingPolicy();
  if (typeof hiResMs !== 'number' || !isFinite(hiResMs)) return 0;
  let v = Math.floor(hiResMs / p.timeOriginStepMs) * p.timeOriginStepMs;
  if (p.addPerOriginJitter) v += stableJitter(originKey(origin) || 'origin', p.jitterMaxMs);
  return v;
}

// clampTimeout 裁决 setTimeout(fn, delay) 的实际延迟。
function clampTimeout(requestedDelayMs, nestingDepth, activeTimerCount, policy) {
  const p = policy || defaultTimingPolicy();
  let delay = typeof requestedDelayMs === 'number' && isFinite(requestedDelayMs) && requestedDelayMs > 0
    ? requestedDelayMs : 0;
  let clamped = false;
  if (nestingDepth >= p.nestedDepthThreshold && delay < p.nestedTimeoutFloorMs) {
    delay = p.nestedTimeoutFloorMs;
    clamped = true;
  } else if (delay < p.minTimeoutMs) {
    delay = p.minTimeoutMs;
    clamped = true;
  }
  const flooded = activeTimerCount >= p.maxActiveTimersPerOrigin;
  return {
    delayMs: delay,
    clamped,
    reason: clamped ? TG_REASON.NESTED_TIMER_CLAMPED : '',
    accepted: !flooded,
    rejectReason: flooded ? TG_REASON.TIMER_FLOOD : '',
  };
}

class TimingGuard {
  constructor(policy) {
    this.policy = policy || defaultTimingPolicy();
    this.activeTimers = new Map();
  }

  // decideSab 裁决 SharedArrayBuffer / Atomics 是否可用。
  // ctx: {origin, crossOriginIsolated}
  decideSab(ctx) {
    if (!this.policy.requireIsolationForSab) return { allowed: true, reason: '' };
    if (ctx && ctx.crossOriginIsolated === true) return { allowed: true, reason: '' };
    return { allowed: false, reason: TG_REASON.NOT_CROSS_ORIGIN_ISOLATED };
  }

  quantizeNow(origin, hiResMs) {
    return quantizeNow(origin, hiResMs, this.policy);
  }
  quantizeTimeOrigin(origin, hiResMs) {
    return quantizeTimeOrigin(origin, hiResMs, this.policy);
  }

  schedule(origin, requestedDelayMs, nestingDepth) {
    const key = originKey(origin) || 'unknown';
    const count = this.activeTimers.get(key) || 0;
    const r = clampTimeout(requestedDelayMs, nestingDepth || 0, count, this.policy);
    if (r.accepted) this.activeTimers.set(key, count + 1);
    return r;
  }

  timerFiredOrCleared(origin) {
    const key = originKey(origin) || 'unknown';
    this.activeTimers.set(key, Math.max(0, (this.activeTimers.get(key) || 1) - 1));
  }

  // redactMemory 裁剪 performance.memory 字段。
  redactMemory(mem) {
    if (this.policy.exposePerformanceMemory !== true || !mem) {
      return { redacted: true, reason: TG_REASON.MEMORY_FIELD_REDACTED };
    }
    return {
      redacted: false,
      usedJSHeapSize: mem.usedJSHeapSize,
      totalJSHeapSize: mem.totalJSHeapSize,
      jsHeapSizeLimit: mem.jsHeapSizeLimit,
    };
  }
}

module.exports = {
  TG_ALLOW, TG_DENY, TG_REASON,
  defaultTimingPolicy, originKey, stableJitter,
  quantizeNow, quantizeTimeOrigin, clampTimeout, TimingGuard,
};
