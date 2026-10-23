'use strict';

// computepressureguard.js —— Compute Pressure API（ComputePressureObserver，cpu/power）裁决内核。
//
// 威胁模型：
//   1. 持续高采样率的 CPU/功耗状态可侧信道推断用户在做什么：视频会议负载、游戏、挖矿、
//      是否在渲染另一个标签的敏感内容，是一条跨标签活动侧信道；
//   2. sampleInterval 设成极小值形成高频轮询，功耗与数据量放大；
//   3. 三方/不可见文档在后台持续订阅，长期画像设备性能与活跃节律；
//   4. 未知 source（未来扩展的硬件传感器）被默认放行；
//   5. 非安全上下文。
//
// 纯逻辑。

const CU_ALLOW = 'allow';
const CU_DENY = 'deny';

const CU_REASON = Object.freeze({
  BAD_CONTEXT: 'cu-bad-context',
  INSECURE_ORIGIN: 'cu-insecure-origin',
  THIRD_PARTY: 'cu-third-party',
  BACKGROUND_BLOCKED: 'cu-background-blocked',
  UNKNOWN_SOURCE: 'cu-unknown-source',
  INTERVAL_TOO_SMALL: 'cu-interval-too-small',
  TOO_MANY_OBSERVERS: 'cu-too-many-observers',
});

const CU_KNOWN_SOURCES = Object.freeze(['cpu', 'power']);

function defaultComputePressurePolicy() {
  return {
    requireHttps: true,
    blockThirdParty: true,
    requireVisible: true,
    allowedSources: CU_KNOWN_SOURCES.slice(),
    minSampleIntervalMs: 1000,
    maxObserversPerOrigin: 2,
  };
}

class ComputePressureGuard {
  constructor(policy) {
    this.policy = policy || defaultComputePressurePolicy();
    this.observers = new Map();
  }

  // decideObserve 裁决 observer.observe([sources], {sampleInterval})。
  decideObserve(ctx, sources, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: CU_DENY, reason: CU_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: CU_DENY, reason: CU_REASON.INSECURE_ORIGIN };
    if (pol.blockThirdParty && ctx.isTopFrame === false) return { decision: CU_DENY, reason: CU_REASON.THIRD_PARTY };
    if (pol.requireVisible && ctx.visible === false) return { decision: CU_DENY, reason: CU_REASON.BACKGROUND_BLOCKED };

    const list = Array.isArray(sources) && sources.length > 0 ? sources : ['cpu'];
    for (const src of list) {
      if (pol.allowedSources.indexOf(src) < 0) return { decision: CU_DENY, reason: CU_REASON.UNKNOWN_SOURCE, source: src };
    }
    const opt = options && typeof options === 'object' ? options : {};
    if (typeof opt.sampleInterval === 'number' && opt.sampleInterval < pol.minSampleIntervalMs) {
      return { decision: CU_DENY, reason: CU_REASON.INTERVAL_TOO_SMALL, interval: opt.sampleInterval };
    }

    const n = this.observers.get(ctx.origin) || 0;
    if (n >= pol.maxObserversPerOrigin) return { decision: CU_DENY, reason: CU_REASON.TOO_MANY_OBSERVERS };
    this.observers.set(ctx.origin, n + 1);
    return { decision: CU_ALLOW, reason: '', interval: typeof opt.sampleInterval === 'number' ? opt.sampleInterval : pol.minSampleIntervalMs };
  }

  unobserve(ctx) {
    const n = this.observers.get(ctx.origin) || 0;
    if (n > 0) this.observers.set(ctx.origin, n - 1);
  }
}

module.exports = {
  CU_ALLOW, CU_DENY, CU_REASON, CU_KNOWN_SOURCES,
  defaultComputePressurePolicy, ComputePressureGuard,
};
