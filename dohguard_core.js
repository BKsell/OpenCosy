'use strict';
const { isObj } = require('./modutil_core');

const { validateDohServer } = require('./dohguard_host_core');

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

// normalizeMode 把设置值归一到合法模式；非法值回退 automatic。
function normalizeMode(mode) {
  const all = new Set(Object.values(SECURE_DNS_MODES));
  return all.has(mode) ? mode : DEFAULT_MODE;
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

module.exports = { DEFAULT_MODE, KNOWN_PROVIDERS, SECURE_DNS_MODES, createDohLedger, getProviderById, normalizeMode, resolveControls, resolveServer, ...require('./dohguard_host_core') };
