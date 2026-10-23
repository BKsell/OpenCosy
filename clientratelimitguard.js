'use strict'

// clientratelimitguard.js —— 浏览器侧出向请求的令牌桶限流与突发守卫。
//
// 威胁模型：
//   恶意页面可在后台对单一主机高频发请求（端口探测、登录爆破、配合刷新放大打内网接口、对自身
//   更新端点刷量）。浏览器层对"每目标主机"的请求做令牌桶限流，可抑制脚本化高频访问，同时放行
//   正常浏览突发。本模块是纯内存令牌桶（可按 host 分桶），不依赖计时器之外的状态，不使用正则。

const RL_REASON = Object.freeze({
  OVER_LIMIT: 'request-rate-exceeds-bucket-capacity',
  BURST_TOO_HIGH: 'instantaneous-burst-exceeds-max-concurrent-starts',
  INVALID_PARAM: 'rate-limit-parameter-invalid'
})

class RateBucket {
  // capacity：突发容量；refillPerMs：每毫秒补充令牌数。
  constructor (capacity, refillPerMs, now) {
    // refillPerMs 允许为 0（表示不补充令牌，纯容量桶）。
    if (!(capacity > 0) || !(refillPerMs >= 0)) {
      throw new Error('RateBucket requires positive capacity and non-negative refill rate')
    }
    this.capacity = capacity
    this.refill = refillPerMs
    this.tokens = capacity
    this.last = typeof now === 'number' ? now : 0
  }

  // 尝试取 n 个令牌。now 毫秒；返回是否允许（不允许不扣令牌）。
  tryTake (n, now) {
    if (!(n > 0)) return false
    const elapsed = now - this.last
    if (elapsed > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.refill)
      this.last = now
    }
    if (this.tokens + 1e-9 >= n) {
      this.tokens -= n
      return true
    }
    return false
  }
}

class ClientRateLimitGuard {
  // opts: { capacity, refillPerMs, maxBurst, now }
  constructor (opts) {
    const o = opts || {}
    this.capacity = typeof o.capacity === 'number' ? o.capacity : 20
    this.refillPerMs = typeof o.refillPerMs === 'number' ? o.refillPerMs : 0.02
    this.maxBurst = typeof o.maxBurst === 'number' ? o.maxBurst : 8
    this.clock = typeof o.now === 'function' ? o.now : function () { return Date.now() }
    this.buckets = new Map()
    this.inflight = new Map()
  }

  bucketFor (host) {
    let b = this.buckets.get(host)
    if (!b) {
      b = new RateBucket(this.capacity, this.refillPerMs, this.clock())
      this.buckets.set(host, b)
    }
    return b
  }

  // 发起一个到 host 的请求前调用。
  acquire (host, cost) {
    const n = typeof cost === 'number' ? cost : 1
    const findings = []
    if (!(n > 0)) findings.push({ reason: RL_REASON.INVALID_PARAM })
    const cur = this.inflight.get(host) || 0
    if (cur + n > this.maxBurst) findings.push({ reason: RL_REASON.BURST_TOO_HIGH })
    const allowed = this.bucketFor(host).tryTake(n, this.clock())
    if (!allowed) findings.push({ reason: RL_REASON.OVER_LIMIT })
    if (findings.length === 0) {
      this.inflight.set(host, cur + n)
      return { safe: true, findings: findings }
    }
    return { safe: false, findings: findings }
  }

  // 请求结束释放并发计数。
  release (host, cost) {
    const n = typeof cost === 'number' ? cost : 1
    const cur = this.inflight.get(host) || 0
    this.inflight.set(host, Math.max(0, cur - n))
  }
}

module.exports = Object.freeze({
  RL_REASON: RL_REASON,
  RateBucket: RateBucket,
  ClientRateLimitGuard: ClientRateLimitGuard
})
