'use strict';

const PROBE_TIMEOUT_MS = 8000;
const OFFLINE_RETRY_MS = 15000;

const STATE = {
  ONLINE: 'online',
  OFFLINE: 'offline',
  CAPTIVE: 'captive',
  SLOW: 'slow',
  UNKNOWN: 'unknown'
};

function normalizeProbe(raw) {
  if (!raw || typeof raw !== 'object') return { state: STATE.UNKNOWN, latencyMs: null, status: 0 };
  const status = Number.isFinite(Number(raw.status)) ? Number(raw.status) : 0;
  const latency = Number.isFinite(Number(raw.latencyMs)) ? Number(raw.latencyMs) : null;
  if (status >= 200 && status < 400) {
    if (latency !== null && latency > PROBE_TIMEOUT_MS / 2) {
      return { state: STATE.SLOW, latencyMs: latency, status };
    }
    return { state: STATE.ONLINE, latencyMs: latency, status };
  }
  if (status >= 500) return { state: STATE.OFFLINE, latencyMs: latency, status };
  if (status === 0) return { state: STATE.OFFLINE, latencyMs: latency, status };
  return { state: STATE.UNKNOWN, latencyMs: latency, status };
}

function detectCaptive(probeResults) {
  if (!Array.isArray(probeResults)) return false;
  let redirected = 0;
  for (const item of probeResults) {
    if (!item || typeof item !== 'object') continue;
    const expected = typeof item.expectedHost === 'string' ? item.expectedHost.toLowerCase() : '';
    const actual = typeof item.finalHost === 'string' ? item.finalHost.toLowerCase() : '';
    if (expected && actual && expected !== actual) redirected += 1;
  }
  return redirected >= 2;
}

function classifyNetwork(navigatorOnline, probeResults) {
  if (navigatorOnline === false) {
    return { state: STATE.OFFLINE, reason: 'navigator-offline', latencyMs: null };
  }
  if (detectCaptive(probeResults)) {
    return { state: STATE.CAPTIVE, reason: 'captive-portal', latencyMs: null };
  }
  if (!Array.isArray(probeResults) || probeResults.length === 0) {
    return { state: STATE.UNKNOWN, reason: 'no-probe', latencyMs: null };
  }
  const probes = probeResults.map(normalizeProbe);
  const online = probes.filter((p) => p.state === STATE.ONLINE || p.state === STATE.SLOW);
  if (online.length === 0) {
    return { state: STATE.OFFLINE, reason: 'all-probe-failed', latencyMs: null };
  }
  const slowest = probes.reduce((max, p) => (p.latencyMs !== null && p.latencyMs > max ? p.latencyMs : max), 0);
  const degraded = probes.some((p) => p.state === STATE.SLOW);
  return {
    state: degraded ? STATE.SLOW : STATE.ONLINE,
    reason: degraded ? 'high-latency' : 'ok',
    latencyMs: slowest
  };
}

function offlinePagePolicy(network) {
  const state = network && network.state ? network.state : STATE.UNKNOWN;
  if (state === STATE.OFFLINE) {
    return {
      showOfflinePage: true,
      allowCache: true,
      retryAfterMs: OFFLINE_RETRY_MS,
      message: '当前网络不可用，正在显示已缓存内容'
    };
  }
  if (state === STATE.CAPTIVE) {
    return {
      showOfflinePage: true,
      allowCache: false,
      retryAfterMs: OFFLINE_RETRY_MS,
      message: '检测到需要登录的公共网络，请先完成认证'
    };
  }
  if (state === STATE.SLOW) {
    return { showOfflinePage: false, allowCache: true, retryAfterMs: 0, message: '网络较慢，已降低自动刷新频率' };
  }
  return { showOfflinePage: false, allowCache: true, retryAfterMs: 0, message: '' };
}

function shouldRetryNow(policy, elapsedMs) {
  if (!policy || policy.retryAfterMs <= 0) return false;
  const elapsed = Number.isFinite(Number(elapsedMs)) ? Number(elapsedMs) : 0;
  return elapsed >= policy.retryAfterMs;
}

function describeNetwork(network) {
  if (!network || !network.state) return '网络状态未知';
  const label = {
    online: '网络正常',
    slow: '网络较慢',
    offline: '网络已断开',
    captive: '需认证的公共网络',
    unknown: '网络状态未知'
  }[network.state] || '网络状态未知';
  if (network.latencyMs) return label + ' · ' + network.latencyMs + 'ms';
  return label;
}

module.exports = {
  PROBE_TIMEOUT_MS,
  OFFLINE_RETRY_MS,
  STATE,
  normalizeProbe,
  detectCaptive,
  classifyNetwork,
  offlinePagePolicy,
  shouldRetryNow,
  describeNetwork
};
