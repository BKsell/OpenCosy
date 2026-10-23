'use strict';

// webtransportguard.js —— WebTransport（HTTP/3 datagram/stream）连接与数据报裁决内核。
//
// 威胁模型：
//   1. WebTransport 走 QUIC，datagram 无回流、无传统缓存，常规代理/内容审计难以感知，
//      是隐蔽出网与数据外泄通道；
//   2. 页面可连向任意 host:port，对内网地址（管理面板、元数据 169.254.169.254）构成 SSRF；
//   3. serverCertificateHashes 自签固定证书若不校验有效期，可被固定到恶意/过期证书；
//   4. datagram 高 QPS / 超大 MTU 被用于洪水与放大；incoming/unidirectional stream 无限创建
//      耗尽连接句柄；
//   5. congestionControl/端口连向非常见服务端口（如 22/3389/6379）做端口探测。
//
// 纯逻辑。

const WT_ALLOW = 'allow';
const WT_DENY = 'deny';

const WT_REASON = Object.freeze({
  BAD_CONTEXT: 'wt-bad-context',
  INSECURE_ORIGIN: 'wt-insecure-origin',
  BAD_URL_SCHEME: 'wt-bad-url-scheme',
  TARGET_PRIVATE_ADDRESS: 'wt-target-private-address',
  PORT_BLOCKED: 'wt-port-blocked',
  BAD_CERT_HASH: 'wt-bad-cert-hash',
  CERT_HASH_EXPIRED: 'wt-cert-hash-expired',
  DATAGRAM_RATE_TOO_HIGH: 'wt-datagram-rate-too-high',
  DATAGRAM_TOO_LARGE: 'wt-datagram-too-large',
  TOO_MANY_STREAMS: 'wt-too-many-streams',
});

const WT_BLOCKED_PORTS = Object.freeze([22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 6379, 27017]);
const WT_MAX_DATAGRAM_BYTES = 1350;

function defaultWebTransportPolicy() {
  return {
    requireHttps: true,
    blockPrivateTargets: true,
    blockedPorts: WT_BLOCKED_PORTS.slice(),
    allowServerCertificateHashes: false,
    maxDatagramBytes: WT_MAX_DATAGRAM_BYTES,
    maxDatagramsPerSecond: 100,
    maxIncomingStreams: 64,
  };
}

function hostPortOf(url) {
  if (typeof url !== 'string') return { scheme: '', host: '', port: 0 };
  const c = url.indexOf(':');
  if (c <= 0) return { scheme: '', host: '', port: 0 };
  const scheme = url.slice(0, c).toLowerCase();
  let rest = url.slice(c + 1);
  if (rest.indexOf('//') === 0) rest = rest.slice(2);
  let hostPort = rest;
  for (const ch of ['/', '?', '#']) {
    const p = hostPort.indexOf(ch);
    if (p >= 0) hostPort = hostPort.slice(0, p);
  }
  if (hostPort.indexOf('@') >= 0) hostPort = hostPort.slice(hostPort.lastIndexOf('@') + 1);
  let host = hostPort;
  let port = 0;
  if (host.indexOf('[') === 0) {
    const rb = host.indexOf(']');
    host = rb > 0 ? host.slice(1, rb) : host;
    const after = hostPort.slice(rb + 1);
    if (after.indexOf(':') === 0) port = Number(after.slice(1)) || 0;
  } else {
    const pc = hostPort.lastIndexOf(':');
    if (pc > 0) { host = hostPort.slice(0, pc); port = Number(hostPort.slice(pc + 1)) || 0; }
  }
  return { scheme, host: host.toLowerCase(), port };
}

function parseIpv4(host) {
  const parts = host.split('.');
  if (parts.length !== 4) return null;
  let ip = 0;
  for (const seg of parts) {
    if (seg.length === 0 || seg.length > 3) return null;
    for (let i = 0; i < seg.length; i++) {
      const c = seg.charCodeAt(i);
      if (c < 48 || c > 57) return null;
    }
    const v = Number(seg);
    if (v > 255) return null;
    ip = ip * 256 + v;
  }
  return ip;
}
function isPrivateOrSpecial(host) {
  if (host === 'localhost' || host.slice(-10) === '.localhost') return true;
  const ip = parseIpv4(host);
  if (ip === null) return false;
  const a = Math.floor(ip / 0x1000000) & 0xff;
  const b = (ip >> 16) & 0xff;
  if (a === 0 || a === 127 || a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true; // 含云元数据
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isHex(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!((c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70))) return false;
  }
  return true;
}

class WebTransportGuard {
  constructor(policy, clock) {
    this.policy = policy || defaultWebTransportPolicy();
    this.clock = typeof clock === 'function' ? clock : (() => Date.now());
    this.datagramLog = new Map();
  }

  // decideConnect 裁决 new WebTransport(url, options)。
  decideConnect(ctx, url, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: WT_DENY, reason: WT_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: WT_DENY, reason: WT_REASON.INSECURE_ORIGIN };

    const { scheme, host, port } = hostPortOf(url);
    if (scheme !== 'https') return { decision: WT_DENY, reason: WT_REASON.BAD_URL_SCHEME, scheme };
    if (pol.blockPrivateTargets && isPrivateOrSpecial(host)) {
      return { decision: WT_DENY, reason: WT_REASON.TARGET_PRIVATE_ADDRESS, host };
    }
    if (port !== 0 && pol.blockedPorts.indexOf(port) >= 0) {
      return { decision: WT_DENY, reason: WT_REASON.PORT_BLOCKED, port };
    }

    const opt = options && typeof options === 'object' ? options : {};
    const hashes = Array.isArray(opt.serverCertificateHashes) ? opt.serverCertificateHashes : [];
    if (hashes.length > 0) {
      if (!pol.allowServerCertificateHashes) return { decision: WT_DENY, reason: WT_REASON.BAD_CERT_HASH };
      for (const hsh of hashes) {
        if (!hsh || (hsh.algorithm !== 'sha-256') || !isHex(hsh.value) || hsh.value.length !== 64) {
          return { decision: WT_DENY, reason: WT_REASON.BAD_CERT_HASH };
        }
        if (typeof hsh.validityExpiry === 'number' && hsh.validityExpiry * 1000 < this.clock()) {
          return { decision: WT_DENY, reason: WT_REASON.CERT_HASH_EXPIRED };
        }
      }
    }
    return { decision: WT_ALLOW, reason: '', host, port };
  }

  // decideDatagram 运行期数据报裁决（速率/大小）。
  decideDatagram(ctx, bytes) {
    const pol = this.policy;
    if (typeof bytes === 'number' && bytes > pol.maxDatagramBytes) {
      return { decision: WT_DENY, reason: WT_REASON.DATAGRAM_TOO_LARGE, bytes };
    }
    const now = this.clock();
    const key = ctx && ctx.origin;
    const arr = this.datagramLog.get(key) || [];
    const fresh = arr.filter((ts) => now - ts < 1000);
    if (fresh.length >= pol.maxDatagramsPerSecond) {
      this.datagramLog.set(key, fresh);
      return { decision: WT_DENY, reason: WT_REASON.DATAGRAM_RATE_TOO_HIGH, perSecond: fresh.length };
    }
    fresh.push(now);
    this.datagramLog.set(key, fresh);
    return { decision: WT_ALLOW, reason: '' };
  }
}

module.exports = {
  WT_ALLOW, WT_DENY, WT_REASON, WT_BLOCKED_PORTS, WT_MAX_DATAGRAM_BYTES,
  defaultWebTransportPolicy, hostPortOf, parseIpv4, isPrivateOrSpecial, isHex, WebTransportGuard,
};
