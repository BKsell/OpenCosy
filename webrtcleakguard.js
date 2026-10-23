'use strict';

// webrtcleakguard.js —— RTCPeerConnection 的 ICE/STUN/TURN 与候选地址泄漏裁决内核。
//
// 威胁模型：
//   1. 恶意页面通过 host candidate 直接拿到本机内网 IP（10/192.168/172.16）与
//      网卡枚举，绕过 VPN 暴露真实位置；mDNS(.local) 混淆出现前这是标配指纹；
//   2. srflx 候选暴露公网 IP，配合 STUN 服务器做用户在线追踪；
//   3. 页面自带任意 STUN/TURN 服务器，把真实 IP 发给攻击者控制的收集端；
//   4. TURN 凭据 URI 使用 data:/javascript 等非法 scheme，或凭据长期不过期；
//   5. iceTransportPolicy:'all' + 任意 iceServers 最大化信息收集。
//
// 纯逻辑，IPv4/IPv6 与私网/链路本地判定全部手写字符解析，不用正则。

const WR_DENY = 'deny';
const WR_ALLOW = 'allow';

const WR_REASON = Object.freeze({
  BAD_ORIGIN: 'wr-bad-origin',
  BLOCKED_ORIGIN: 'wr-blocked-origin',
  INSECURE_CONTEXT: 'wr-insecure-context',
  NO_GESTURE_REQUIRED_HINT: 'wr-policy-relax-requires-gesture',
  BAD_ICE_SERVER_URI: 'wr-bad-ice-server-uri',
  NON_HTTPS_TURN_CREDENTIAL_URL: 'wr-non-https-turn-credential-url',
  ICE_SERVER_NOT_ALLOWED: 'wr-ice-server-not-allowed',
  TOO_MANY_ICE_SERVERS: 'wr-too-many-ice-servers',
  PERMISSION_THROTTLED: 'wr-permission-throttled',
});

const CAND = Object.freeze({ HOST: 'host', SRFLX: 'srflx', PRFLX: 'prflx', RELAY: 'relay' });

function defaultWebRtcPolicy() {
  return {
    requireSecureContext: true,
    // 默认最严：只走 mDNS 混淆的 host 与允许的 relay，隐藏字面内网/公网 IP。
    allowLiteralHostIp: false,
    allowMdnsHostname: true,
    allowSrflx: false,
    allowRelay: true,
    allowPrivateSrflx: false,
    maxIceServers: 4,
    relaxPolicyMinIntervalMs: 5000,
    // 只允许显式白名单的 STUN/TURN 主机；空数组表示使用浏览器默认、禁止页面自带。
    allowedIceServerHosts: [],
    allowCustomIceServers: false,
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

// parseIpv4 解析点分四段；返回四个 0..255 数字，失败返回 null。
function parseIpv4(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  const out = [];
  for (const p of parts) {
    if (p.length < 1 || p.length > 3) return null;
    let v = 0;
    for (let i = 0; i < p.length; i++) {
      const c = p.charCodeAt(i);
      if (c < 48 || c > 57) return null;
      v = v * 10 + (c - 48);
    }
    if (v > 255) return null;
    out.push(v);
  }
  return out;
}

function isPrivateOrLocalIPv4(parts) {
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true; // 链路本地
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // 组播/保留
  return false;
}

// parseIpv6Groups 仅做粗解析返回是否为 IPv6 字面量及前几段（用于本地地址判定）。
function ipv6Scope(s) {
  const addr = s.indexOf('[') === 0 ? s.slice(1, s.indexOf(']')) : s;
  const lower = addr.toLowerCase();
  if (lower === '::1') return 'loopback';
  if (lower.indexOf('fe80') === 0 || lower.indexOf('fec0') === 0 || lower.indexOf('fc') === 0 || lower.indexOf('fd') === 0) {
    return 'local';
  }
  // IPv4 映射 ::ffff:a.b.c.d
  const marker = '::ffff:';
  if (lower.indexOf(marker) >= 0) {
    const v4 = parseIpv4(addr.slice(addr.lastIndexOf(':') + 1));
    if (v4 && isPrivateOrLocalIPv4(v4)) return 'local';
  }
  return 'global';
}

function endsWithMdns(host) {
  const h = host.toLowerCase();
  return h === 'local' || h.endsWith('.local') || h.endsWith('.local.');
}

function hostOfUrl(uri) {
  const colon = uri.indexOf(':');
  if (colon <= 0) return '';
  let rest = uri.slice(colon + 1);
  if (rest.indexOf('//') === 0) rest = rest.slice(2);
  const slash = rest.indexOf('/');
  if (slash >= 0) rest = rest.slice(0, slash);
  const at = rest.indexOf('@');
  if (at >= 0) rest = rest.slice(at + 1);
  const bracket = rest.indexOf(']');
  if (rest.indexOf('[') === 0 && bracket > 0) return rest.slice(1, bracket).toLowerCase();
  const portColon = rest.lastIndexOf(':');
  if (portColon > 0 && parseIpv4(rest.slice(0, portColon)) === null) rest = rest.slice(0, portColon);
  return rest.toLowerCase();
}

// validateIceUri 仅接受 stun:/stuns:/turn:/turns:，拒绝数据/脚本 scheme。
function iceUriScheme(uri) {
  if (typeof uri !== 'string') return '';
  const colon = uri.indexOf(':');
  if (colon <= 0) return '';
  const sch = uri.slice(0, colon).toLowerCase();
  if (sch === 'stun' || sch === 'stuns' || sch === 'turn' || sch === 'turns') return sch;
  return '';
}

class WebRtcLeakGuard {
  constructor(policy) {
    this.policy = policy || defaultWebRtcPolicy();
    this.relaxes = new Map();
  }

  // validateIceServers 校验页面传入的 RTCConfiguration.iceServers。
  validateIceServers(iceServers) {
    const pol = this.policy;
    if (!iceServers) return { ok: true, hosts: [] };
    const list = Array.isArray(iceServers) ? iceServers : [];
    if (list.length > pol.maxIceServers) return { ok: false, reason: WR_REASON.TOO_MANY_ICE_SERVERS };
    const hosts = [];
    for (const srv of list) {
      const urls = srv && srv.urls;
      const arr = Array.isArray(urls) ? urls : (urls ? [urls] : []);
      for (const raw of arr) {
        const sch = iceUriScheme(raw);
        if (!sch) return { ok: false, reason: WR_REASON.BAD_ICE_SERVER_URI, uri: raw };
        if ((sch === 'turn' || sch === 'turns') && srv.credential && typeof srv.credential === 'string') {
          // 长生命周期静态凭据风险交给上层；这里只核 scheme。
        }
        const host = hostOfUrl(raw);
        hosts.push(host);
        if (!pol.allowCustomIceServers) {
          return { ok: false, reason: WR_REASON.ICE_SERVER_NOT_ALLOWED, host };
        }
        if (pol.allowedIceServerHosts.length) {
          const ok = pol.allowedIceServerHosts.some((h) => host === h || host.endsWith('.' + h));
          if (!ok) return { ok: false, reason: WR_REASON.ICE_SERVER_NOT_ALLOWED, host };
        }
      }
    }
    return { ok: true, hosts };
  }

  // decideConnection 裁决是否允许按此配置建立 PeerConnection。
  decideConnection(ctx, config) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { allowed: false, reason: WR_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { allowed: false, reason: WR_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { allowed: false, reason: WR_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { allowed: false, reason: WR_REASON.BLOCKED_ORIGIN };
    const srvCheck = this.validateIceServers(config && config.iceServers);
    if (!srvCheck.ok) return { allowed: false, reason: srvCheck.reason, host: srvCheck.host };
    return {
      allowed: true,
      reason: '',
      effectivePolicy: this._effectivePolicy(config),
    };
  }

  _effectivePolicy(config) {
    // 默认强制 relay，页面无法自行放宽到 all，除非上层显式授予。
    const p = config && config.iceTransportPolicy;
    if (p === 'relay') return 'relay';
    return this.policy.allowRelay ? 'relay' : 'all';
  }

  // filterCandidate 对一条 ICE candidate 决定是否放行给上层/网络。
  // cand: {type, address, relatedAddress}
  filterCandidate(cand) {
    const pol = this.policy;
    const type = cand && cand.type;
    const addr = cand && typeof cand.address === 'string' ? cand.address : '';

    if (type === CAND.RELAY) return { emit: pol.allowRelay };
    if (type === CAND.SRFLX || type === CAND.PRFLX) {
      const v4 = parseIpv4(addr);
      if (v4 && isPrivateOrLocalIPv4(v4)) return { emit: pol.allowPrivateSrflx };
      return { emit: pol.allowSrflx };
    }
    if (type === CAND.HOST) {
      if (endsWithMdns(addr)) return { emit: pol.allowMdnsHostname };
      const v4 = parseIpv4(addr);
      if (v4) {
        if (isPrivateOrLocalIPv4(v4)) return { emit: pol.allowLiteralHostIp };
        return { emit: pol.allowLiteralHostIp };
      }
      const scope = ipv6Scope(addr);
      if (scope !== 'global') return { emit: pol.allowLiteralHostIp };
      return { emit: pol.allowLiteralHostIp };
    }
    return { emit: false };
  }

  // requestRelaxedPolicy 处理页面/用户临时放宽（如确实需要 P2P），带节流与手势。
  requestRelaxedPolicy(ctx) {
    const pol = this.policy;
    const key = originKey(ctx && ctx.origin);
    if (!key) return { allowed: false, reason: WR_REASON.BAD_ORIGIN };
    if (ctx.hasUserGesture !== true) return { allowed: false, reason: WR_REASON.NO_GESTURE_REQUIRED_HINT };
    const now = ctx.now || 0;
    if (this.relaxes.has(key) && now - this.relaxes.get(key) < pol.relaxPolicyMinIntervalMs) {
      return { allowed: false, reason: WR_REASON.PERMISSION_THROTTLED };
    }
    this.relaxes.set(key, now);
    return { allowed: true, reason: '' };
  }
}

module.exports = {
  WR_ALLOW, WR_DENY, WR_REASON, CAND,
  defaultWebRtcPolicy, originKey, parseIpv4, isPrivateOrLocalIPv4,
  ipv6Scope, endsWithMdns, hostOfUrl, iceUriScheme, WebRtcLeakGuard,
};
