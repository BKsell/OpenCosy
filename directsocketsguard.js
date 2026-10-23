'use strict';

// directsocketsguard.js —— Direct Sockets（TCPSocket/UDPSocket/TCPServerSocket）原始套接字裁决内核。
//
// 威胁模型：
//   1. Direct Sockets 让网页直接发原始 TCP/UDP：可绕过同源/代理/防火墙审计，对内网任意主机
//      端口做扫描与协议探活（SSRF 的浏览器侧形态），还能驱动 Redis/MySQL/内网管理口；
//   2. 连接本地环回/链路本地/私网/RFC1918 是最高风险；TCPServerSocket 监听端口等于把本地
//      服务暴露给网页控制；
//   3. remotePort/addressRange 脏值（0、65536、CIDR 广播/网络地址）需拦；
//   4. UDP 可伪造源、做放大攻击；keepalive 长连接 + 大量 socket 耗尽 fd；
//   5. 用 mDNS/.local 或十进制/八进制 IP 混淆绕过字符串匹配。
//
// 纯逻辑，不打开真实套接字。

const DS_ALLOW = 'allow';
const DS_DENY = 'deny';

const DS_REASON = Object.freeze({
  BAD_CONTEXT: 'ds-bad-context',
  NO_GESTURE: 'ds-no-gesture',
  INSECURE_ORIGIN: 'ds-insecure-origin',
  API_DISABLED: 'ds-api-disabled',
  BAD_ADDRESS: 'ds-bad-address',
  PRIVATE_TARGET: 'ds-private-target',
  BAD_PORT: 'ds-bad-port',
  PORT_BLOCKED: 'ds-port-blocked',
  SERVER_SOCKET_DISABLED: 'ds-server-socket-disabled',
  UDP_DISABLED: 'ds-udp-disabled',
  TOO_MANY_SOCKETS: 'ds-too-many-sockets',
  ADDRESS_RANGE_TOO_WIDE: 'ds-address-range-too-wide',
});

// 浏览器 Direct Sockets 默认动态/受限端口外，额外点杀常见内网服务端口。
const DS_BLOCKED_PORTS = Object.freeze([
  22, 23, 2323, 25, 53, 110, 135, 137, 138, 139, 143, 389, 445, 465, 587, 636, 993, 995,
  1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5985, 5986, 6379, 8086, 9200, 11211, 27017,
]);

function defaultDirectSocketsPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    tcpEnabled: true,
    udpEnabled: false,
    serverSocketEnabled: false,
    blockPrivateTargets: true,
    allowedTargetHosts: [],
    blockedPorts: DS_BLOCKED_PORTS.slice(),
    minEphemeralPort: 1024,
    maxSocketsPerOrigin: 4,
    maxAddressRangeSize: 16,
  };
}

// normalizeIpv4 处理点分十进制（含全整型/长整型/八进制混淆的常见形态）。
function normalizeIpv4(input) {
  if (typeof input !== 'string') return null;
  let s = input.toLowerCase();
  if (s.indexOf('0x') === 0) {
    const n = parseHex(s.slice(2));
    if (n === null || n > 0xffffffff) return null;
    return ipv4FromInt(n);
  }
  const parts = s.split('.');
  if (parts.length < 1 || parts.length > 4) return null;
  const values = [];
  for (let i = 0; i < parts.length; i++) {
    const seg = parts[i];
    if (seg.length === 0) return null;
    let v;
    if (seg.indexOf('0x') === 0) {
      v = parseHex(seg.slice(2));
    } else if (seg.length > 1 && seg.charAt(0) === '0') {
      v = parseOctal(seg);
    } else {
      v = parseDecimal(seg);
    }
    if (v === null) return null;
    values.push(v);
  }
  // 合并末段（类 inet_aton 短形式），仅保守支持末段 >255 的两/三/四段。
  if (values.length === 1) return ipv4FromInt(values[0]);
  return composeShort(values);
}

// composeShort 按 a.b.c.d / a.b.c / a.b / a 短形式组合。
function composeShort(values) {
  if (values.length === 4) {
    for (const v of values) if (v > 255) return null;
    return ipv4FromInt(((values[0] * 256 + values[1]) * 256 + values[2]) * 256 + values[3]);
  }
  if (values.length === 3) {
    if (values[0] > 255 || values[1] > 255 || values[2] > 0xffff) return null;
    return ipv4FromInt((values[0] * 256 + values[1]) * 65536 + values[2]);
  }
  if (values.length === 2) {
    if (values[0] > 255 || values[1] > 0xffffff) return null;
    return ipv4FromInt(values[0] * 16777216 + values[1]);
  }
  if (values[0] > 0xffffffff) return null;
  return ipv4FromInt(values[0]);
}

function ipv4FromInt(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}
function parseDecimal(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 57) return null;
  }
  return Number(s);
}
function parseHex(s) {
  if (s.length === 0) return null;
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    let d;
    if (c >= 48 && c <= 57) d = c - 48;
    else if (c >= 97 && c <= 102) d = c - 87;
    else return null;
    n = n * 16 + d;
  }
  return n;
}
function parseOctal(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 48 || c > 55) return null;
    n = n * 8 + (c - 48);
  }
  return n;
}

// looksNumericDotted：仅由数字、点与十六进制 x 组成（IP 字面量形态），不含普通域名字母。
function looksNumericDotted(s) {
  let hasDigit = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 48 && c <= 57) { hasDigit = true; continue; }
    if (c === 46 || c === 120 || c === 88) continue; // '.' 'x' 'X'
    return false;
  }
  return hasDigit;
}

function classifyIpv4(ip) {
  const parts = ip.split('.').map(Number);
  const a = parts[0];
  const b = parts[1];
  if (a === 0 || a === 127) return 'loopback';
  if (a === 10) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 169 && b === 254) return 'linklocal';
  if (a === 100 && b >= 64 && b <= 127) return 'cgNAT';
  if (a >= 224) return 'reserved';
  return 'public';
}

class DirectSocketsGuard {
  constructor(policy) {
    this.policy = policy || defaultDirectSocketsPolicy();
    this.openCount = new Map();
  }

  _gate(ctx, needGesture) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return DS_REASON.BAD_CONTEXT;
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return DS_REASON.INSECURE_ORIGIN;
    if (needGesture && pol.requireUserGesture && ctx.userGesture !== true) return DS_REASON.NO_GESTURE;
    return '';
  }

  _checkHost(host) {
    if (typeof host !== 'string' || host.length === 0) return { ok: false, reason: DS_REASON.BAD_ADDRESS };
    if (host === 'localhost' || host.slice(-10) === '.localhost' || host.slice(-6) === '.local') {
      return { ok: false, reason: DS_REASON.PRIVATE_TARGET, class: 'local-name' };
    }
    // 全数字/点分（含 0x/前导 0）形态必须能被归一化，否则是脏 IP（如 999.1.1.1）。
    if (looksNumericDotted(host) && normalizeIpv4(host) === null) {
      return { ok: false, reason: DS_REASON.BAD_ADDRESS, host };
    }
    const norm = normalizeIpv4(host);
    if (norm !== null) {
      const cls = classifyIpv4(norm);
      if (cls !== 'public') return { ok: false, reason: DS_REASON.PRIVATE_TARGET, class: cls, normalized: norm };
    }
    if (this.policy.allowedTargetHosts.length > 0) {
      const h = host.toLowerCase();
      const ok = this.policy.allowedTargetHosts.some((x) => h === x || h.endsWith('.' + x));
      if (!ok) return { ok: false, reason: DS_REASON.BAD_ADDRESS, host };
    }
    return { ok: true };
  }

  _checkPort(port) {
    if (typeof port !== 'number' || !Number.isInteger(port) || port < 0 || port > 65535) {
      return { ok: false, reason: DS_REASON.BAD_PORT };
    }
    if (this.policy.blockedPorts.indexOf(port) >= 0) return { ok: false, reason: DS_REASON.PORT_BLOCKED, port };
    return { ok: true };
  }

  // decideConnect 裁决 TCP/UDP 连接。proto: 'tcp'|'udp'。
  decideConnect(ctx, proto, host, port) {
    const pol = this.policy;
    const bad = this._gate(ctx, true);
    if (bad) return { decision: DS_DENY, reason: bad };
    if (proto === 'udp' && !pol.udpEnabled) return { decision: DS_DENY, reason: DS_REASON.UDP_DISABLED };
    if (proto !== 'tcp' && proto !== 'udp') return { decision: DS_DENY, reason: DS_REASON.API_DISABLED };

    const h = this._checkHost(host);
    if (!h.ok) return Object.assign({ decision: DS_DENY }, h);
    const p = this._checkPort(port);
    if (!p.ok) return Object.assign({ decision: DS_DENY }, p);

    const n = this.openCount.get(ctx.origin) || 0;
    if (n >= pol.maxSocketsPerOrigin) return { decision: DS_DENY, reason: DS_REASON.TOO_MANY_SOCKETS };
    this.openCount.set(ctx.origin, n + 1);
    return { decision: DS_ALLOW, reason: '' };
  }

  // decideListen 裁决 TCPServerSocket 监听。
  decideListen(ctx, localPort) {
    const pol = this.policy;
    const bad = this._gate(ctx, true);
    if (bad) return { decision: DS_DENY, reason: bad };
    if (!pol.serverSocketEnabled) return { decision: DS_DENY, reason: DS_REASON.SERVER_SOCKET_DISABLED };
    if (localPort !== undefined && localPort !== 0) {
      const p = this._checkPort(localPort);
      if (!p.ok) return Object.assign({ decision: DS_DENY }, p);
    }
    return { decision: DS_ALLOW, reason: '' };
  }

  release(ctx) {
    const n = this.openCount.get(ctx.origin) || 0;
    if (n > 0) this.openCount.set(ctx.origin, n - 1);
  }
}

module.exports = {
  DS_ALLOW, DS_DENY, DS_REASON, DS_BLOCKED_PORTS,
  defaultDirectSocketsPolicy, normalizeIpv4, classifyIpv4, DirectSocketsGuard,
};
