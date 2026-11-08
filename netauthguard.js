'use strict';

// netauthguard.js —— 网络身份认证治理纯逻辑内核（不依赖 Electron）。
//
// 现代浏览器对两类“操作系统/网络层”身份事件有自己的安全策略，而 Electron
// 默认把它们交给原生对话框、甚至静默复用当前系统登录凭据：
//
//   1) HTTP 401/407（Basic/Digest/NTLM/Negotiate）。
//      - 子框架 / 跨源图片脚本触发的 401 常被用来“凭据探测”：攻击者页面塞
//        一个 <img src="http://intranet/">，浏览器若自动带 NTLM 凭据，就能
//        探内网主机是否存活、当前用户是谁。现代浏览器只对顶层主框架的 401
//        弹框，子框架一律静默失败。
//      - 恶意站点还能对一堆主机连续返回 401 制造“认证弹框轰炸”，把用户点烦
//        后随手输入口令，或直接用弹出框做 UI 红鲱鱼。必须按主机做限流。
//      - NTLM/Negotiate 绝不能静默用当前操作系统身份，必须显式让用户知情。
//
//   2) TLS 客户端证书（select-client-certificate）。
//      多证书环境下若自动选一张发给服务器，等于把“我有某 CA 签发的身份”
//      这一隐私主动泄露给任意站点。现代浏览器默认不自动发送，必须用户明确
//      选择。本模块在没有“用户为该主机明确记住的指纹”时永远返回不选择。
//
// main.js 只负责接 Electron 事件与 IPC；所有“该不该弹、按谁限流、证书能不能
// 自动发”的判定集中在本文件，用 node:test 做表驱动单测。

// 已知的 Web 身份认证方案。unknown 方案不弹框（fail-closed），避免出现我们
// 不了解语义的新方案时把凭据交给它。
const KNOWN_AUTH_SCHEMES = new Set(['basic', 'digest', 'ntlm', 'negotiate']);

// 弹框限流：同一认证主体在滑动窗口内最多弹多少次，超限后进入冷却。
// 数值故意偏保守——正常用户极少在一分钟内对同一台主机连续 401 五次。
const DEFAULT_MAX_PROMPTS_IN_WINDOW = 5;
const DEFAULT_PROMPT_WINDOW_MS = 60 * 1000;
const DEFAULT_PROMPT_COOLDOWN_MS = 5 * 60 * 1000;

// 一次认证弹框等待用户的最长时间。超时自动取消，避免悬挂的回调卡住请求，
// 也避免攻击者用一堆永不交互的 401 堆积待处理项。
const AUTH_PROMPT_TIMEOUT_MS = 60 * 1000;

// 待处理认证请求的总量上限（跨所有主机），防止内存被无限堆积。
const MAX_PENDING_PROMPTS = 32;

// 入站字符串长度上限，超长一律截断/拒绝，防止异常输入撑爆日志与 IPC。
const MAX_REALM_CHARS = 300;
const MAX_HOST_CHARS = 255;
const MAX_USERNAME_CHARS = 512;
const MAX_PASSWORD_CHARS = 4096;

function clampText(value, max) {
  if (typeof value !== 'string') return '';
  const cleaned = value.replace(/[\x00-\x1f\x7f]/g, ' ').trim();
  return cleaned.length > max ? cleaned.slice(0, max) : cleaned;
}

function lowerTrim(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

// parseHttpUrl 只接受 http/https，其它协议（file/ftp/javascript/...）返回 null。
function parseHttpUrl(raw) {
  if (typeof raw !== 'string' || raw === '') return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  return u;
}

// authHostKey 是限流 / 记忆的主体键：scheme + host(:port)。不带路径，避免同一
// 主机换个 URL 就绕过限流；显式端口参与键，区分同一主机上的不同服务。
function authHostKey(rawUrl) {
  const u = parseHttpUrl(rawUrl);
  if (!u) return '';
  let host = u.hostname.toLowerCase();
  if (host.length > MAX_HOST_CHARS) host = host.slice(0, MAX_HOST_CHARS);
  if (u.port) return `${u.protocol}//${host}:${u.port}`;
  return `${u.protocol}//${host}`;
}

function normalizeScheme(authInfo) {
  return lowerTrim(authInfo && authInfo.scheme);
}

// classifyServerAuth 判定一次“服务器 401”该如何处理。
// 返回 { decision:'prompt'|'cancel', reason, key, scheme, realm, host }。
function classifyServerAuth({ url, isMainFrame, authInfo } = {}) {
  const u = parseHttpUrl(url);
  const key = authHostKey(url);
  const scheme = normalizeScheme(authInfo);
  const realm = clampText(authInfo && authInfo.realm, MAX_REALM_CHARS);
  const base = { key, scheme, realm, host: u ? u.hostname : '' };

  if (!u || !key) return { ...base, decision: 'cancel', reason: 'non-http-url' };
  // 子框架（iframe / 跨源媒体）的 401 静默失败，这是凭据探测的主要入口。
  if (isMainFrame !== true) {
    return { ...base, decision: 'cancel', reason: 'subframe-credential-probe' };
  }
  if (!KNOWN_AUTH_SCHEMES.has(scheme)) {
    return { ...base, decision: 'cancel', reason: 'unknown-auth-scheme' };
  }
  return { ...base, decision: 'prompt', reason: 'main-frame-401' };
}

// classifyProxyAuth 判定一次“代理 407”。代理认证同样限流，但没有主/子框架之分；
// 只认已知方案，且 key 以 proxy: 前缀与服务器认证区分。
function classifyProxyAuth({ url, authInfo } = {}) {
  const scheme = normalizeScheme(authInfo);
  const u = parseHttpUrl(url);
  const proxyHost = clampText(authInfo && authInfo.host, MAX_HOST_CHARS);
  const proxyPort = Number(authInfo && authInfo.port);
  let key = 'proxy:';
  if (proxyHost) {
    key += Number.isInteger(proxyPort) && proxyPort > 0 ? `${proxyHost}:${proxyPort}` : proxyHost;
  } else if (u) {
    key += 'session';
  } else {
    key += 'unknown';
  }
  const realm = clampText(authInfo && authInfo.realm, MAX_REALM_CHARS);
  if (!KNOWN_AUTH_SCHEMES.has(scheme)) {
    return { decision: 'cancel', reason: 'unknown-auth-scheme', key, scheme, realm, host: proxyHost };
  }
  return { decision: 'prompt', reason: 'proxy-407', key, scheme, realm, host: proxyHost };
}

// AuthPromptRateLimiter 是按 key 的滑动窗口限流器，并在触发上限后给该主体一段
// 冷却期（冷却期内直接拒绝，不再计数）。时间由调用方注入，便于单测。
class AuthPromptRateLimiter {
  constructor({
    max = DEFAULT_MAX_PROMPTS_IN_WINDOW,
    windowMs = DEFAULT_PROMPT_WINDOW_MS,
    cooldownMs = DEFAULT_PROMPT_COOLDOWN_MS,
  } = {}) {
    this.max = max;
    this.windowMs = windowMs;
    this.cooldownMs = cooldownMs;
    this.hits = new Map();   // key -> number[] 时间戳
    this.coolingUntil = new Map(); // key -> 冷却结束时间戳
  }

  // 返回 { allow, reason }。allow=false 时 reason 为 'cooldown' 或 'rate-limited'。
  request(key, now) {
    if (typeof key !== 'string' || key === '') return { allow: false, reason: 'bad-key' };
    const t = Number.isFinite(now) ? now : Date.now();

    const until = this.coolingUntil.get(key) || 0;
    if (t < until) return { allow: false, reason: 'cooldown' };
    if (t >= until && until !== 0) this.coolingUntil.delete(key);

    const cutoff = t - this.windowMs;
    const stamps = (this.hits.get(key) || []).filter(ts => ts > cutoff);
    if (stamps.length >= this.max) {
      this.coolingUntil.set(key, t + this.cooldownMs);
      this.hits.set(key, stamps);
      return { allow: false, reason: 'rate-limited' };
    }
    stamps.push(t);
    this.hits.set(key, stamps);
    return { allow: true, reason: 'ok' };
  }

  // 用户成功完成一次认证后调用：清掉计数与冷却，避免合法输入被历史轰炸拖累。
  reset(key) {
    this.hits.delete(key);
    this.coolingUntil.delete(key);
  }

  // 仅供测试 / 面板观察，不参与安全决策。
  size() {
    return this.hits.size;
  }
}

// normalizeCertFingerprint 统一 Electron 客户端证书指纹。
// Electron 给出的 certificate.fingerprint 形如 "SHA256:AB:CD:.."，冒号大小写
// 不一。这里去掉冒号并小写，得到稳定的十六进制，便于和“记住的选择”比较。
function normalizeCertFingerprint(value) {
  if (typeof value !== 'string') return '';
  const hex = value.replace(/^(sha1|sha256)\s*:/i, '').replace(/[^0-9a-fA-F]/g, '');
  return hex.toLowerCase();
}

// chooseClientCertificate 决定要发送哪张客户端证书。
// 默认策略：没有“用户为该主机明确记住的指纹”时绝不自动选择（返回 index=-1）。
// rememberedFingerprint 为空 => 取消；给了就必须在候选列表里精确命中，否则也取消。
function chooseClientCertificate({ certificateList = [], rememberedFingerprint = '' } = {}) {
  if (!Array.isArray(certificateList) || certificateList.length === 0) {
    return { index: -1, reason: 'no-certificate' };
  }
  const wanted = normalizeCertFingerprint(rememberedFingerprint);
  if (!wanted) return { index: -1, reason: 'no-remembered-choice' };
  for (let i = 0; i < certificateList.length; i++) {
    const cert = certificateList[i];
    if (normalizeCertFingerprint(cert && cert.fingerprint) === wanted) {
      return { index: i, reason: 'remembered' };
    }
  }
  return { index: -1, reason: 'remembered-cert-absent' };
}

// sanitizeAuthSubmit 校验/净化用户从渲染层提交回来的账号口令。
// 账号必填；口令允许空串（部分内网 Basic 确实空密码），但必须是字符串。
// 返回 { ok, username, password }；超长或类型错误一律拒绝，不做截断后放行，
// 因为“悄悄截断口令”会让用户把错误的凭据发给服务器。
function sanitizeAuthSubmit(raw) {
  if (!raw || typeof raw !== 'object') return { ok: false, reason: 'bad-payload' };
  if (typeof raw.username !== 'string' || typeof raw.password !== 'string') {
    return { ok: false, reason: 'bad-type' };
  }
  const username = raw.username.replace(/[\x00-\x1f\x7f]/g, '').trim();
  const password = raw.password.replace(/[\x00]/g, '');
  if (username.length === 0 || username.length > MAX_USERNAME_CHARS) {
    return { ok: false, reason: 'bad-username' };
  }
  if (password.length > MAX_PASSWORD_CHARS) {
    return { ok: false, reason: 'password-too-long' };
  }
  return { ok: true, username, password };
}

// describeAuthScheme 给弹框一个人类可读的方案名（日志/UI 用），未知返回空串。
function describeAuthScheme(scheme) {
  switch (lowerTrim(scheme)) {
    case 'basic': return 'HTTP Basic 基本认证';
    case 'digest': return 'HTTP Digest 摘要认证';
    case 'ntlm': return 'NTLM / Windows 身份认证';
    case 'negotiate': return 'Negotiate / SPNEGO（Kerberos）';
    default: return '';
  }
}

// 最多为多少台主机记住客户端证书选择；超出淘汰最久未用的。客户端证书是强身份，
// 台账故意比普通站点设置小得多，避免长期累积出一份“访问过哪些需证书内网”的画像。
const MAX_REMEMBERED_CERT_HOSTS = 100;
const MAX_ISSUER_CHARS = 200;
const MAX_SUBJECT_CHARS = 200;
const MAX_SERIAL_CHARS = 128;

// certHostKey 与 authHostKey 一致（scheme://host:port），但客户端证书场景只应出现在
// https。这里仍复用 authHostKey，确保“记住证书”和“认证限流”看到的是同一台主体。
function certHostKey(rawUrl) {
  return authHostKey(rawUrl);
}

// summarizeClientCert 抽取证书里用于展示/记录的最小非敏感字段。不取公钥本体，
// 只留指纹与签发者/主题的短摘要。
function summarizeClientCert(certificate) {
  const c = certificate && typeof certificate === 'object' ? certificate : {};
  const fingerprint = normalizeCertFingerprint(c.fingerprint);
  return {
    fingerprint,
    issuer: clampText(c.issuerName || (c.issuer && c.issuer.name) || '', MAX_ISSUER_CHARS),
    subject: clampText(c.subjectName || (c.subject && c.subject.name) || '', MAX_SUBJECT_CHARS),
    serialNumber: clampText(c.serialNumber || c.serial || '', MAX_SERIAL_CHARS),
  };
}

// sanitizeCertChoiceRecord 把从磁盘读出的一条记录净化为可信结构；不合法返回 null。
function sanitizeCertChoiceRecord(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const host = clampText(raw.host, MAX_HOST_CHARS);
  const fingerprint = normalizeCertFingerprint(raw.fingerprint);
  if (!host || !fingerprint) return null;
  const updatedAt = Number(raw.updatedAt);
  return {
    host,
    fingerprint,
    issuer: clampText(raw.issuer, MAX_ISSUER_CHARS),
    subject: clampText(raw.subject, MAX_SUBJECT_CHARS),
    serialNumber: clampText(raw.serialNumber, MAX_SERIAL_CHARS),
    updatedAt: Number.isFinite(updatedAt) ? updatedAt : 0,
  };
}

// RememberedClientCertStore 是“主机 -> 记住的客户端证书指纹”的有界台账。
// 纯内存 + toJSON/loadJSON，落盘由 main.js 负责，便于单测不碰文件系统。
class RememberedClientCertStore {
  constructor({ max = MAX_REMEMBERED_CERT_HOSTS } = {}) {
    this.max = max;
    this.map = new Map();
  }

  // 已存在则更新并刷新 updatedAt；新增超容时淘汰 updatedAt 最小的一条。
  remember(host, certificate, now = Date.now()) {
    const key = certHostKey(`https://${host}/`);
    const hostKey = key || clampText(host, MAX_HOST_CHARS);
    if (!hostKey) return false;
    const summary = summarizeClientCert(certificate);
    if (!summary.fingerprint) return false;
    const record = { host: hostKey, ...summary, updatedAt: now };
    if (this.map.has(hostKey)) {
      this.map.set(hostKey, record);
      return true;
    }
    if (this.map.size >= this.max) {
      let oldestKey = null;
      let oldestTime = Infinity;
      for (const [k, v] of this.map) {
        if (v.updatedAt < oldestTime) {
          oldestTime = v.updatedAt;
          oldestKey = k;
        }
      }
      if (oldestKey) this.map.delete(oldestKey);
    }
    this.map.set(hostKey, record);
    return true;
  }

  get(host) {
    return this.map.get(certHostKey(`https://${host}/`)) || this.map.get(clampText(host, MAX_HOST_CHARS)) || null;
  }

  forget(host) {
    const key = certHostKey(`https://${host}/`);
    return this.map.delete(key) || this.map.delete(clampText(host, MAX_HOST_CHARS));
  }

  clear() {
    this.map.clear();
  }

  list() {
    return Array.from(this.map.values()).sort((a, b) => b.updatedAt - a.updatedAt);
  }

  toJSON() {
    return { version: 1, choices: this.list() };
  }

  loadJSON(raw) {
    let data;
    try {
      data = typeof raw === 'string' ? JSON.parse(raw) : raw;
    } catch {
      return 0;
    }
    const entries = data && Array.isArray(data.choices) ? data.choices : null;
    if (!entries) return 0;
    let loaded = 0;
    for (const e of entries) {
      const rec = sanitizeCertChoiceRecord(e);
      if (!rec) continue;
      this.map.set(rec.host, rec);
      loaded++;
      if (this.map.size >= this.max) break;
    }
    return loaded;
  }
}

// AuthPromptStats 聚合网络认证拦截/弹框计数，供安全页面板展示，不落敏感内容。
// 维度只到“原因码 + 方案”，绝不记录账号、口令、realm 原文。
const MAX_STATS_KEYS = 200;

class AuthPromptStats {
  constructor() {
    this.total = 0;                 // 进入认证流程的事件总数
    this.prompted = 0;             // 真正向用户弹框的次数
    this.cancelled = 0;            // 被策略静默取消的次数
    this.succeeded = 0;            // 用户成功提交并通过的次数
    this.rateLimited = 0;          // 触发限流/冷却的次数
    this.certSuppressed = 0;       // 客户端证书被默认不发送的次数
    this.byReason = new Map();     // reason -> count
    this.byScheme = new Map();     // scheme -> count
  }

  bump(mapRef, key) {
    const k = String(key || 'unknown');
    if (mapRef.size >= MAX_STATS_KEYS && !mapRef.has(k)) return;
    mapRef.set(k, (mapRef.get(k) || 0) + 1);
  }

  recordEvent({ decision, reason, scheme } = {}) {
    this.total++;
    if (scheme) this.bump(this.byScheme, lowerTrim(scheme));
    if (reason) this.bump(this.byReason, reason);
    if (decision === 'prompt') this.prompted++;
    if (decision === 'cancel') this.cancelled++;
  }

  recordRateLimited() {
    this.rateLimited++;
  }

  recordSuccess() {
    this.succeeded++;
  }

  recordCertSuppressed() {
    this.certSuppressed++;
  }

  toJSON() {
    return {
      total: this.total,
      prompted: this.prompted,
      cancelled: this.cancelled,
      succeeded: this.succeeded,
      rateLimited: this.rateLimited,
      certSuppressed: this.certSuppressed,
      byReason: Object.fromEntries(this.byReason),
      byScheme: Object.fromEntries(this.byScheme),
    };
  }
}

module.exports = {
  KNOWN_AUTH_SCHEMES,
  DEFAULT_MAX_PROMPTS_IN_WINDOW,
  DEFAULT_PROMPT_WINDOW_MS,
  DEFAULT_PROMPT_COOLDOWN_MS,
  AUTH_PROMPT_TIMEOUT_MS,
  MAX_PENDING_PROMPTS,
  MAX_REALM_CHARS,
  MAX_HOST_CHARS,
  MAX_USERNAME_CHARS,
  MAX_PASSWORD_CHARS,
  MAX_REMEMBERED_CERT_HOSTS,
  MAX_ISSUER_CHARS,
  MAX_SUBJECT_CHARS,
  MAX_SERIAL_CHARS,
  MAX_STATS_KEYS,
  parseHttpUrl,
  authHostKey,
  normalizeScheme,
  classifyServerAuth,
  classifyProxyAuth,
  AuthPromptRateLimiter,
  normalizeCertFingerprint,
  chooseClientCertificate,
  sanitizeAuthSubmit,
  describeAuthScheme,
  certHostKey,
  summarizeClientCert,
  sanitizeCertChoiceRecord,
  RememberedClientCertStore,
  AuthPromptStats,
};
