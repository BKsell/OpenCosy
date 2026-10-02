'use strict';

// dohguard.js —— 安全 DNS（DNS-over-HTTPS）选择与校验内核（无 Electron 依赖，可单测）。
//
// 默认情况下系统 DNS 是明文 UDP：同一网络里的任何人都能看到你在解析哪些域名，
// 也能通过污染应答把你引导到钓鱼站。现代浏览器都支持把 DNS 查询经 HTTPS 发往
// 可信解析器（DoH / Secure DNS）。本模块负责：
//   1. 模式归一：off（关闭）/ automatic（跟随系统，能升级则升级）/ secure（强制）；
//   2. 可信解析器模板白名单与“自定义服务器 URL”的严格校验；
//   3. 拒绝把 DoH 指向回环 / 内网 / 链路本地（那等于把全部域名泄露给本地攻击者，
//      也构成 SSRF 面）、拒绝非 https、拒绝带用户名密码的 URL；
//   4. 输出可直接喂给 session.setHostResolverControls 的控件参数（特性存在时）。
//
// 这里只做纯判定，不直接触碰 session；老版本 Electron 没有该 API 时主进程应
// 静默降级（typeof 探测），不影响浏览。

const SECURE_DNS_MODES = Object.freeze({
  OFF: 'off',
  AUTOMATIC: 'automatic',
  SECURE: 'secure',
});
const DEFAULT_MODE = SECURE_DNS_MODES.AUTOMATIC;

// Chromium 接收的是 RFC 8484 URI-template（可带 {?dns} 供 GET 大响应）。
// 只收录 https、解析与隐私口碑明确的公共解析器。
const KNOWN_PROVIDERS = Object.freeze([
  { id: 'cloudflare', name: 'Cloudflare (1.1.1.1)', template: 'https://cloudflare-dns.com/dns-query' },
  { id: 'google', name: 'Google Public DNS', template: 'https://dns.google/dns-query' },
  { id: 'quad9', name: 'Quad9 (9.9.9.9)', template: 'https://dns.quad9.net/dns-query' },
  { id: 'alidns', name: '阿里公共 DNS', template: 'https://dns.alidns.com/dns-query' },
  { id: 'dnspod', name: '腾讯 DNSPod', template: 'https://doh.pub/dns-query' },
]);

function isObj(v) {
  return v !== null && typeof v === 'object';
}

// normalizeMode 把设置值归一到合法模式；非法值回退 automatic。
function normalizeMode(mode) {
  const all = new Set(Object.values(SECURE_DNS_MODES));
  return all.has(mode) ? mode : DEFAULT_MODE;
}

// isLoopbackIPv4 / isPrivateIPv4 等按无类别整数比较，避免字符串误判。
function parseIPv4(host) {
  if (typeof host !== 'string') return null;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map(Number);
  for (const n of parts) {
    if (n < 0 || n > 255) return null;
  }
  // 拒绝前导零歧义（如 010.0.0.1 八进制/十进制不一致）。
  for (let i = 0; i < 4; i++) {
    if (m[i + 1].length > 1 && m[i + 1][0] === '0') return null;
  }
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + (parts[2] << 8) + parts[3];
}

function ipv4IsLoopback(ip) {
  // 127.0.0.0/8
  return (ip >>> 24) === 127;
}

function ipv4IsPrivate(ip) {
  if (ipv4IsLoopback(ip)) return true;
  const a = (ip >>> 24) & 0xff;
  const b = (ip >>> 16) & 0xff;
  if (a === 10) return true;                       // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true;         // 192.168.0.0/16
  if (a === 169 && b === 254) return true;         // 169.254.0.0/16 链路本地/云元数据
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 0) return true;                        // 0.0.0.0/8 本机网络

  return false;
}

// parseIPv6 仅用于识别字面量回环 / 链路本地 / 唯一本地地址，做保守判定。
// 返回规范化后的小写十六进制串（展开 ::），失败返回 null。
function parseIPv6(host) {
  if (typeof host !== 'string') return null;
  let h = host.toLowerCase();
  if (h.startsWith('[')) {
    if (!h.endsWith(']')) return null;
    h = h.slice(1, -1);
  }
  if (h.indexOf('.') !== -1) {
    // 嵌 IPv4 仅接受标准 IPv4-mapped（::ffff:a.b.c.d）；其它形式（含已废弃的
    // IPv4-compatible ::a.b.c.d）保守处理，避免怪异字面量绕过私网判定。
    const lastColon = h.lastIndexOf(':');
    const prefix = h.slice(0, lastColon + 1);
    const v4 = parseIPv4(h.slice(lastColon + 1));
    if (v4 === null) return null;
    if (prefix.endsWith('::ffff:')) {
      // 兼容完整映射前缀；::7f00:1 这类环回同样落到 v4 私网判定。
      return ipv4IsPrivate(v4) ? 'private' : 'public-v4mapped';
    }
    // 非标准映射前缀：私网仍判私网（如 ::127.0.0.1），公网则按非法拒绝。
    return ipv4IsPrivate(v4) ? 'private' : null;
  }
  const dbl = h.split('::');
  if (dbl.length > 2) return null;
  let groups;
  if (dbl.length === 2) {
    const head = dbl[0] ? dbl[0].split(':') : [];
    const tail = dbl[1] ? dbl[1].split(':') : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = head.concat(new Array(missing).fill('0'), tail);
  } else {
    groups = h.split(':');
  }
  if (groups.length !== 8) return null;
  const norm = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    norm.push(g.padStart(4, '0'));
  }
  return norm.join(':');
}

function ipv6IsPrivate(norm) {
  if (norm === 'private') return true;
  if (norm === 'public-v4mapped') return false;
  if (typeof norm !== 'string' || norm.length !== 39) return false;
  const first = norm.slice(0, 4);
  if (first === '0000' && norm.endsWith('0001')) return true; // ::1
  if (first.startsWith('fe8') || first.startsWith('fe9') ||
      first.startsWith('fea') || first.startsWith('feb')) return true; // fe80::/10
  if (first[0] === 'f' && (first[1] === 'c' || first[1] === 'd')) return true; // fc00::/7
  if (norm.startsWith('0000:0000:0000:0000:0000:ffff')) {
    // 非 mapped-private 已在 parse 阶段标 public-v4mapped，理论上不会到这。
    return false;
  }
  return false;
}

// hostIsPrivateLiteral 判断主机是否为回环 / 内网 / 链路本地的 IP 字面量或本机名。
// 普通域名（即便其公网解析恰好在内网）无法在不发 DNS 的情况下判定，这里不拦。
function hostIsPrivateLiteral(host) {
  if (typeof host !== 'string' || !host) return true;
  const h = host.toLowerCase().replace(/\.$/, '');
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (h.indexOf(':') !== -1) {
    const norm = parseIPv6(h);
    if (norm === null) return true; // 非法 IPv6 字面量，保守拒绝
    return ipv6IsPrivate(norm);
  }
  const v4 = parseIPv4(h);
  if (v4 !== null) return ipv4IsPrivate(v4);
  // 形如四段点分数字却无法解析（越界 / 前导零）的字面量，绝不能当普通域名放行，
  // 否则会被解析器按数字 IP 歧义处理，绕过私网判定。
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  // 纯整数 / 十六进制整数主机名在部分解析器里会被当作 32 位 IP，同样拒绝。
  if (/^\d+$/.test(h) || /^0x[0-9a-f]+$/i.test(h)) return true;
  return false;
}

// validateDohServer 校验自定义 / 白名单 DoH 服务器 URL。
// 返回 { ok:true, template } 或 { ok:false, reason }。
function validateDohServer(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return { ok: false, reason: 'empty' };
  }
  let u;
  try {
    u = new URL(rawUrl.trim());
  } catch {
    return { ok: false, reason: 'invalid-url' };
  }
  if (u.protocol !== 'https:') return { ok: false, reason: 'not-https' };
  if (u.username || u.password) return { ok: false, reason: 'credentials' };
  if (!u.hostname) return { ok: false, reason: 'no-host' };
  if (hostIsPrivateLiteral(u.hostname)) return { ok: false, reason: 'private-or-loopback' };
  // 仅允许默认 443 或显式 https 高端口，禁止把模板指向常见内网管理端口。
  if (u.port && !(u.port === '443')) {
    const portNum = Number(u.port);
    if (!Number.isInteger(portNum) || portNum < 1024 || portNum > 65535) {
      return { ok: false, reason: 'bad-port' };
    }
  }
  if (u.search && u.search.indexOf('dns') === -1) {
    // 允许带 {?dns} 模板或无查询；不允许奇怪的固定查询串。
    if (!/\{\?dns\}/.test(u.search)) return { ok: false, reason: 'bad-query' };
  }
  if (u.hash) return { ok: false, reason: 'fragment' };
  // 规范化：去查询里的 {?dns} 之外参数这里不动，直接用主机 + /dns-query 路径判定。
  if (!u.pathname || u.pathname === '/') return { ok: false, reason: 'no-path' };
  return { ok: true, template: u.toString() };
}

function getProviderById(id) {
  return KNOWN_PROVIDERS.find((p) => p.id === id) || null;
}

// resolveServer 根据 provider id 或自定义 URL 决定最终模板。
// 返回 { ok, template, source } 或 { ok:false, reason }。
function resolveServer(providerId, customUrl) {
  if (providerId && providerId !== 'custom') {
    const p = getProviderById(providerId);
    if (p) return { ok: true, template: p.template, source: p.id };
    return { ok: false, reason: 'unknown-provider' };
  }
  const v = validateDohServer(customUrl);
  if (!v.ok) return { ok: false, reason: v.reason };
  return { ok: true, template: v.template, source: 'custom' };
}

// resolveControls 输出 setHostResolverControls 参数；mode=off 时不指定服务器。
// 返回 { mode, controls, template } 或 { mode:'off', controls:{secureDnsMode:'off'} }。
function resolveControls(options) {
  const opts = isObj(options) ? options : {};
  const mode = normalizeMode(opts.mode);
  if (mode === SECURE_DNS_MODES.OFF) {
    return { mode, controls: { secureDnsMode: SECURE_DNS_MODES.OFF } };
  }
  const srv = resolveServer(opts.provider, opts.customUrl);
  if (!srv.ok) {
    // 自定义地址非法时绝不能“退回明文还显得安全”：automatic 不带服务器，
    // secure 非法则交由调用方提示（这里仍返回 automatic 语义，由 UI 层告警）。
    return {
      mode: SECURE_DNS_MODES.AUTOMATIC,
      controls: { secureDnsMode: SECURE_DNS_MODES.AUTOMATIC },
      warning: srv.reason,
    };
  }
  return {
    mode,
    template: srv.template,
    controls: { secureDnsMode: mode, secureDnsServers: [srv.template] },
  };
}

// createDohLedger 记录模式切换与降级（如 secure 配置非法被降级）。
function createDohLedger(limit) {
  const max = Number.isInteger(limit) && limit > 0 ? limit : 200;
  const rows = [];
  function add(entry) {
    if (!isObj(entry)) return;
    rows.unshift({
      time: Number(entry.time) || Date.now(),
      mode: String(entry.mode || '').slice(0, 16),
      event: String(entry.event || '').slice(0, 32),
      detail: String(entry.detail || '').slice(0, 200),
    });
    if (rows.length > max) rows.length = max;
  }
  function list() { return rows.slice(); }
  function toJSON() { return { version: 1, rows }; }
  function load(data) {
    rows.length = 0;
    if (isObj(data) && Array.isArray(data.rows)) {
      for (const r of data.rows.slice(0, max)) {
        if (isObj(r)) add(r);
      }
    }
  }
  function clear() { rows.length = 0; }
  return { add, list, toJSON, load, clear, size: () => rows.length };
}

module.exports = {
  SECURE_DNS_MODES,
  DEFAULT_MODE,
  KNOWN_PROVIDERS,
  normalizeMode,
  parseIPv4,
  ipv4IsPrivate,
  parseIPv6,
  ipv6IsPrivate,
  hostIsPrivateLiteral,
  validateDohServer,
  getProviderById,
  resolveServer,
  resolveControls,
  createDohLedger,
};
