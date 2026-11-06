'use strict';

const DEFAULT_WINDOW_MS = 10000;
const DEFAULT_PER_HOST_MAX = 12;
const DEFAULT_GLOBAL_MAX = 120;

const REASON = {
  OK: 'ok',
  HOST_LIMIT: 'host-limit',
  GLOBAL_LIMIT: 'global-limit',
};

function normalizeHost(host) {
  if (typeof host !== 'string') {
    return '';
  }
  return host.trim().toLowerCase();
}

class DownloadRateLimiter {
  constructor(options) {
    const opts = options || {};
    this.windowMs = Number.isFinite(opts.windowMs) && opts.windowMs > 0 ? opts.windowMs : DEFAULT_WINDOW_MS;
    this.perHostMax = Number.isInteger(opts.perHostMax) && opts.perHostMax > 0 ? opts.perHostMax : DEFAULT_PER_HOST_MAX;
    this.globalMax = Number.isInteger(opts.globalMax) && opts.globalMax > 0 ? opts.globalMax : DEFAULT_GLOBAL_MAX;
    this.hostBuckets = new Map();
    this.globalTimestamps = [];
  }

  static prune(timestamps, now, windowMs) {
    let drop = 0;
    while (drop < timestamps.length && now - timestamps[drop] >= windowMs) {
      drop += 1;
    }
    if (drop > 0) {
      timestamps.splice(0, drop);
    }
  }

  record(host, now) {
    const current = Number.isFinite(now) ? now : Date.now();
    const key = normalizeHost(host);
    DownloadRateLimiter.prune(this.globalTimestamps, current, this.windowMs);
    const bucket = this.hostBuckets.get(key) || [];
    DownloadRateLimiter.prune(bucket, current, this.windowMs);
    if (bucket.length >= this.perHostMax) {
      this.hostBuckets.set(key, bucket);
      return {
        ok: false,
        reason: REASON.HOST_LIMIT,
        host: key,
        hostCount: bucket.length,
        globalCount: this.globalTimestamps.length,
        retryAfterMs: Math.max(0, this.windowMs - (current - bucket[0])),
      };
    }
    if (this.globalTimestamps.length >= this.globalMax) {
      this.hostBuckets.set(key, bucket);
      return {
        ok: false,
        reason: REASON.GLOBAL_LIMIT,
        host: key,
        hostCount: bucket.length,
        globalCount: this.globalTimestamps.length,
        retryAfterMs: Math.max(0, this.windowMs - (current - this.globalTimestamps[0])),
      };
    }
    bucket.push(current);
    this.hostBuckets.set(key, bucket);
    this.globalTimestamps.push(current);
    return {
      ok: true,
      reason: REASON.OK,
      host: key,
      hostCount: bucket.length,
      globalCount: this.globalTimestamps.length,
      retryAfterMs: 0,
    };
  }

  snapshot(host, now) {
    const current = Number.isFinite(now) ? now : Date.now();
    const key = normalizeHost(host);
    const bucket = this.hostBuckets.get(key) || [];
    DownloadRateLimiter.prune(bucket, current, this.windowMs);
    DownloadRateLimiter.prune(this.globalTimestamps, current, this.windowMs);
    return {
      host: key,
      hostCount: bucket.length,
      hostMax: this.perHostMax,
      globalCount: this.globalTimestamps.length,
      globalMax: this.globalMax,
      windowMs: this.windowMs,
    };
  }

  reset() {
    this.hostBuckets.clear();
    this.globalTimestamps = [];
  }
}

function describeDownloadRateLimit(result) {
  const reason = result && result.reason;
  if (reason === REASON.OK) {
    return '下载频率正常';
  }
  if (reason === REASON.HOST_LIMIT) {
    return '同一主机 10 秒内下载次数超过上限';
  }
  if (reason === REASON.GLOBAL_LIMIT) {
    return '全局 10 秒内下载次数超过上限';
  }
  return '下载频率未通过校验';
}

module.exports = {
  DEFAULT_WINDOW_MS,
  DEFAULT_PER_HOST_MAX,
  DEFAULT_GLOBAL_MAX,
  REASON,
  DownloadRateLimiter,
  describeDownloadRateLimit,
};
