'use strict';

const DEFAULT_GLOBAL_MAX_BYTES = 8 * 1024 * 1024 * 1024;
const DEFAULT_HOST_MAX_BYTES = 3 * 1024 * 1024 * 1024;
const DEFAULT_MAX_HOSTS = 64;

const REASON = {
  OK: 'ok',
  INVALID_HOST: 'invalid-host',
  INVALID_BYTES: 'invalid-bytes',
  GLOBAL_EXCEEDED: 'global-budget-exceeded',
  HOST_EXCEEDED: 'host-budget-exceeded',
  TOO_MANY_HOSTS: 'too-many-hosts',
};

const HOST_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

function normalizeQuotaHost(host) {
  if (typeof host !== 'string') return '';
  const trimmed = host.trim().toLowerCase();
  if (trimmed.length === 0 || trimmed.length > 253) return '';
  if (!HOST_PATTERN.test(trimmed)) return '';
  return trimmed;
}

function safeByteCount(bytes) {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes)) return null;
  if (bytes < 0 || bytes > Number.MAX_SAFE_INTEGER) return null;
  return Math.floor(bytes);
}

function describeQuotaReject(reason, host) {
  switch (reason) {
    case REASON.OK:
      return '下载配额充足';
    case REASON.INVALID_HOST:
      return '下载配额记录缺少合法主机名';
    case REASON.INVALID_BYTES:
      return '下载配额收到非法字节数';
    case REASON.GLOBAL_EXCEEDED:
      return '本次下载将超过全局下载字节预算';
    case REASON.HOST_EXCEEDED:
      return `本次下载将超过主机 ${host || ''} 的下载字节预算`;
    case REASON.TOO_MANY_HOSTS:
      return '同时下载的主机数量超过上限';
    default:
      return '下载配额校验失败';
  }
}

class DownloadQuota {
  constructor(options = {}) {
    this.globalMaxBytes = Number.isFinite(options.globalMaxBytes) && options.globalMaxBytes > 0
      ? options.globalMaxBytes
      : DEFAULT_GLOBAL_MAX_BYTES;
    this.hostMaxBytes = Number.isFinite(options.hostMaxBytes) && options.hostMaxBytes > 0
      ? options.hostMaxBytes
      : DEFAULT_HOST_MAX_BYTES;
    this.maxHosts = Number.isFinite(options.maxHosts) && options.maxHosts > 0
      ? Math.floor(options.maxHosts)
      : DEFAULT_MAX_HOSTS;
    this.totalBytes = 0;
    this.byHost = new Map();
  }

  reserve(host, bytes) {
    const key = normalizeQuotaHost(host);
    if (!key) {
      return { ok: false, reason: REASON.INVALID_HOST, host: '', reservedBytes: 0 };
    }
    const amount = safeByteCount(bytes);
    if (amount === null) {
      return { ok: false, reason: REASON.INVALID_BYTES, host: key, reservedBytes: 0 };
    }
    if (!this.byHost.has(key) && this.byHost.size >= this.maxHosts) {
      return { ok: false, reason: REASON.TOO_MANY_HOSTS, host: key, reservedBytes: 0 };
    }
    if (amount > 0 && this.totalBytes + amount > this.globalMaxBytes) {
      return { ok: false, reason: REASON.GLOBAL_EXCEEDED, host: key, reservedBytes: 0 };
    }
    const hostBytes = this.byHost.get(key) || 0;
    if (amount > 0 && hostBytes + amount > this.hostMaxBytes) {
      return { ok: false, reason: REASON.HOST_EXCEEDED, host: key, reservedBytes: 0 };
    }
    this.totalBytes += amount;
    this.byHost.set(key, hostBytes + amount);
    return { ok: true, reason: REASON.OK, host: key, reservedBytes: amount };
  }

  settle(host, reservedBytes, actualBytes) {
    const key = normalizeQuotaHost(host);
    if (!key) return false;
    const reserved = safeByteCount(reservedBytes);
    const actual = safeByteCount(actualBytes);
    if (reserved === null || actual === null) return false;
    const hostBytes = this.byHost.get(key);
    if (hostBytes === undefined || hostBytes < reserved) return false;
    const delta = actual - reserved;
    if (delta > 0 && this.totalBytes + delta > this.globalMaxBytes) {
      return false;
    }
    if (delta > 0 && hostBytes + delta > this.hostMaxBytes) {
      return false;
    }
    this.totalBytes += delta;
    this.byHost.set(key, hostBytes + delta);
    if (this.byHost.get(key) === 0 && this.byHost.size > 0) {
      this.byHost.delete(key);
    }
    return true;
  }

  release(host, bytes) {
    const key = normalizeQuotaHost(host);
    if (!key) return false;
    const amount = safeByteCount(bytes);
    if (amount === null) return false;
    const hostBytes = this.byHost.get(key);
    if (hostBytes === undefined || hostBytes < amount) return false;
    this.totalBytes -= amount;
    if (this.totalBytes < 0) this.totalBytes = 0;
    if (hostBytes === amount) {
      this.byHost.delete(key);
    } else {
      this.byHost.set(key, hostBytes - amount);
    }
    return true;
  }

  snapshot() {
    const hosts = {};
    for (const [key, value] of this.byHost.entries()) {
      hosts[key] = value;
    }
    return {
      totalBytes: this.totalBytes,
      globalMaxBytes: this.globalMaxBytes,
      hostMaxBytes: this.hostMaxBytes,
      hostCount: this.byHost.size,
      maxHosts: this.maxHosts,
      hosts,
    };
  }
}

module.exports = {
  DownloadQuota,
  REASON,
  DEFAULT_GLOBAL_MAX_BYTES,
  DEFAULT_HOST_MAX_BYTES,
  DEFAULT_MAX_HOSTS,
  normalizeQuotaHost,
  safeByteCount,
  describeQuotaReject,
};
