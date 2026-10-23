'use strict';

// wifidirectguard.js —— Wi-Fi Direct / Local Peer-to-Peer（RTCPeerConnection 本地发现）授权裁决。
//
// 威胁模型：
// 1. 本地 P2P 通道（WebRTC data channel / Wi-Fi Direct 封装）让页面在不经任何服务器的
//    情况下与局域网设备建链，绕过出站代理、SSRF 防护与内容审计；
// 2. 绑定到 0.0.0.0/:: 或网段广播地址，把数据泼到整个二层/三层广播域；
// 3. 无 STUN 时 mDNS .local 候选泄露设备主机名；host 候选直接暴露内网 IP 做指纹；
// 4. ICE candidate 里的 IP 若落在链路本地/环回/私有段，可被用来打内网服务（SSRF 内网面）；
// 5. 超大 candidate 字符串或畸形字段是脏数据。
//
// 纯逻辑：对 RTCConfiguration 与单条 RTCIceCandidate 的地址做判定，不建立真实连接。

const WD_ALLOW = 'allow';
const WD_DENY = 'deny';

const WD_REASON = Object.freeze({
  BAD_CONTEXT: 'wd-bad-context',
  INSECURE_ORIGIN: 'wd-insecure-origin',
  CROSS_ORIGIN_SUBFRAME: 'wd-cross-origin-subframe',
  NO_STUN_OVER_HTTP: 'wd-no-stun-over-http',
  STUN_HOST_BLOCKED: 'wd-stun-host-blocked',
  BAD_BIND_ADDRESS: 'wd-bad-bind-address',
  BROADCAST_BIND: 'wd-broadcast-bind',
  MDNS_HOSTNAME_LEAK: 'wd-mdns-hostname-leak',
  LOCAL_CANDIDATE_PRIVATE: 'wd-local-candidate-private',
  LOOPBACK_CANDIDATE: 'wd-loopback-candidate',
  LINK_LOCAL_CANDIDATE: 'wd-link-local-candidate',
  BAD_CANDIDATE: 'wd-bad-candidate',
  CANDIDATE_TOO_LONG: 'wd-candidate-too-long',
});

const WD_MAX_CANDIDATE_LEN = 1024;

function defaultWifiDirectPolicy() {
  return {
    requireHttps: true,
    blockCrossOriginSubframe: true,
    requireStunHttps: true,
    blockLoopbackStun: true,
    blockedStunHostSuffixes: [],
    allowedBindAddresses: [], // 空=不额外限制（仍受环回/广播/私网规则约束）
    blockLocalPrivateCandidates: false, // host 候选为私网默认仅告警；true 时硬拒
    blockMdnsHostnameCandidates: true,
    maxCandidateLength: WD_MAX_CANDIDATE_LEN,
  };
}

// parseIpv4 解析点分十进制，返回数字或 null（纯字符）。
function parseIpv4(host) {
  if (typeof host !== 'string' || host.length === 0) return null;
  const parts = host.split('.');
  if (parts.length !== 4) return null;
  let ip = 0;
  for (let i = 0; i < 4; i++) {
    const seg = parts[i];
    if (!isAllDigits(seg) || seg.length === 0 || seg.length > 3) return null;
    const v = Number(seg);
    if (v < 0 || v > 255) return null;
    ip = ip * 256 + v;
  }
  return ip;
}

function isAllDigits(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) return false;
  }
  return true;
}

// classifyIpv4 按 RFC1918/环回/链路本地/广播分类。
function classifyIpv4(ip) {
  const a = Math.floor(ip / 0x1000000) & 0xff;
  const b = (ip >> 16) & 0xff;
  if (a === 127) return 'loopback';
  if (a === 0) return 'unspecified';
  if (a === 10) return 'private';
  if (a === 169 && b === 254) return 'linklocal';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 100 && b >= 64 && b <= 127) return 'cgNAT';
  if (a === 224) return 'multicast';
  if (a >= 240) return 'reserved';
  if ((ip & 0xff) === 0 || (ip & 0xff) === 255) return 'broadcastish';
  return 'public';
}

// hostFromUrl 取出 host（纯字符）。
function stunHost(url) {
  if (typeof url !== 'string') return { scheme: '', host: '' };
  const colon = url.indexOf(':');
  if (colon <= 0) return { scheme: '', host: '' };
  const scheme = url.slice(0, colon).toLowerCase();
  let rest = url.slice(colon + 1);
  if (rest.indexOf('//') === 0) rest = rest.slice(2);
  let host = rest;
  for (const ch of ['/', '?', '#']) {
    const p = host.indexOf(ch);
    if (p >= 0) host = host.slice(0, p);
  }
  if (host.indexOf('@') >= 0) host = host.slice(host.lastIndexOf('@') + 1);
  if (host.indexOf('[') === 0) {
    const rb = host.indexOf(']');
    host = rb > 0 ? host.slice(1, rb) : host;
  } else {
    const pc = host.lastIndexOf(':');
    if (pc > 0) host = host.slice(0, pc);
  }
  return { scheme, host: host.toLowerCase() };
}

// evaluateConfig 裁决 RTCConfiguration.iceServers。
function evaluateConfig(config, pol) {
  const cfg = config && typeof config === 'object' ? config : {};
  const servers = Array.isArray(cfg.iceServers) ? cfg.iceServers : [];
  for (let i = 0; i < servers.length; i++) {
    const srv = servers[i];
    const urls = Array.isArray(srv.urls) ? srv.urls : (typeof srv.urls === 'string' ? [srv.urls] : []);
    for (const u of urls) {
      const { scheme, host } = stunHost(u);
      if (scheme !== 'stun' && scheme !== 'stuns' && scheme !== 'turn' && scheme !== 'turns') {
        continue;
      }
      if (pol.requireStunHttps && (scheme === 'stun' || scheme === 'turn')) {
        // stun:/turn: 本身无 TLS，这里仅在与明文传输凭据相关时拦 turn（携带 credential）。
        if (scheme === 'turn' && (srv.credential || srv.username)) {
          return { decision: WD_DENY, reason: WD_REASON.NO_STUN_OVER_HTTP, index: i, url: u };
        }
      }
      if (pol.blockLoopbackStun) {
        const ip = parseIpv4(host);
        if (ip !== null && classifyIpv4(ip) === 'loopback') {
          return { decision: WD_DENY, reason: WD_REASON.STUN_HOST_BLOCKED, index: i, host };
        }
      }
      for (const suf of pol.blockedStunHostSuffixes) {
        const sx = String(suf).toLowerCase();
        if (host === sx || host.endsWith('.' + sx)) {
          return { decision: WD_DENY, reason: WD_REASON.STUN_HOST_BLOCKED, index: i, host };
        }
      }
    }
  }
  return { decision: WD_ALLOW, reason: '' };
}

class WifiDirectGuard {
  constructor(policy) {
    this.policy = policy || defaultWifiDirectPolicy();
  }

  decideConfig(ctx, config) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: WD_DENY, reason: WD_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: WD_DENY, reason: WD_REASON.INSECURE_ORIGIN };
    if (pol.blockCrossOriginSubframe && ctx.isTopFrame === false) return { decision: WD_DENY, reason: WD_REASON.CROSS_ORIGIN_SUBFRAME };
    return evaluateConfig(config, pol);
  }

  // decideCandidate 裁决一条本地 ICE candidate（candidate 字符串或 {address,addressType}）。
  decideCandidate(candidate, addressType) {
    const pol = this.policy;
    let addr = '';
    let type = typeof addressType === 'string' ? addressType : '';
    if (candidate && typeof candidate === 'object' && typeof candidate.address === 'string') {
      addr = candidate.address;
      if (!type && typeof candidate.type === 'string') type = candidate.type;
    } else if (typeof candidate === 'string') {
      if (candidate.length > pol.maxCandidateLength) return { decision: WD_DENY, reason: WD_REASON.CANDIDATE_TOO_LONG };
      addr = extractCandidateAddr(candidate);
      if (!type) type = extractCandidateType(candidate);
    } else {
      return { decision: WD_DENY, reason: WD_REASON.BAD_CANDIDATE };
    }
    if (!addr) return { decision: WD_DENY, reason: WD_REASON.BAD_CANDIDATE };

    // mDNS 混淆主机名（.local）默认视为主机名泄露面。
    if (addr.indexOf('.') > 0 && addr.slice(-6).toLowerCase() === '.local') {
      if (pol.blockMdnsHostnameCandidates) return { decision: WD_DENY, reason: WD_REASON.MDNS_HOSTNAME_LEAK, address: addr };
      return { decision: WD_ALLOW, reason: '' };
    }

    const ip = parseIpv4(addr);
    if (ip === null) return { decision: WD_ALLOW, reason: '' }; // IPv6/域名交给下游
    const cls = classifyIpv4(ip);
    if (cls === 'loopback') return { decision: WD_DENY, reason: WD_REASON.LOOPBACK_CANDIDATE, address: addr };
    if (cls === 'linklocal' || cls === 'multicast' || cls === 'broadcastish' || cls === 'unspecified') {
      return { decision: WD_DENY, reason: WD_REASON.BAD_BIND_ADDRESS, address: addr, class: cls };
    }
    if (pol.blockLocalPrivateCandidates && (cls === 'private' || cls === 'cgNAT')) {
      return { decision: WD_DENY, reason: WD_REASON.LOCAL_CANDIDATE_PRIVATE, address: addr, class: cls };
    }
    return { decision: WD_ALLOW, reason: '', class: cls };
  }
}

// extractCandidateAddr 从 candidate 字符串里取 "typ" 之前的 address（纯字符切分）。
function extractCandidateAddr(c) {
  // 形如: candidate:... udp 21222321 192.0.2.3 54321 typ host
  const typ = c.indexOf(' typ ');
  const head = typ >= 0 ? c.slice(0, typ) : c;
  const toks = head.split(' ');
  // 地址通常是倒数第二个 token（端口前一个）。
  for (let i = toks.length - 1; i >= 0; i--) {
    const t = toks[i];
    if (parseIpv4(t) !== null) return t;
    if (t.indexOf('.') > 0 && t.slice(-6).toLowerCase() === '.local') return t;
  }
  return '';
}
function extractCandidateType(c) {
  const typ = c.indexOf(' typ ');
  if (typ < 0) return '';
  const rest = c.slice(typ + 5).split(' ');
  return rest.length > 0 ? rest[0] : '';
}

module.exports = {
  WD_ALLOW, WD_DENY, WD_REASON,
  defaultWifiDirectPolicy, parseIpv4, classifyIpv4, stunHost,
  evaluateConfig, extractCandidateAddr, extractCandidateType, WifiDirectGuard,
};
